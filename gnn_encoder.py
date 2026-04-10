import os
import torch
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, global_mean_pool, global_max_pool
import networkx as nx
from typing import List, Dict, Any, Tuple
import logging
import threading

from torch_geometric.data import Data, Batch

logger = logging.getLogger(__name__)

class GraphSAGEEncoder(torch.nn.Module):
    """
    Inductive GraphSAGE Encoder.
    Scales to unseen nodes and edges without requiring static relation mappings.
    """
    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int):
        super().__init__()
        # Layer 1: Inductive Aggregation
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        # Layer 2: Inductive Aggregation
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        
        # Linear layers for pooling and final embedding
        self.lin1 = torch.nn.Linear(hidden_channels, hidden_channels)
        self.lin2 = torch.nn.Linear(hidden_channels, out_channels)

    def forward(self, x, edge_index, batch):
        # Initial convolution
        x1 = self.conv1(x, edge_index)
        x1 = F.elu(x1)
        x1 = F.dropout(x1, p=0.2, training=self.training)

        # Second convolution
        x2 = self.conv2(x1, edge_index)
        x2 = F.elu(x2)

        # Pooling: Combine Mean and Max pooling to capture both "average" behavior 
        # and "extreme" (bursty) events in the graph.
        x_mean = global_mean_pool(x2, batch)
        x_max = global_max_pool(x2, batch)
        x_pool = x_mean + x_max

        # Final MLP
        x_out = F.relu(self.lin1(x_pool))
        x_out = self.lin2(x_out)
        return x_out

class TopologicalGraphEncoder:
    """
    Advanced encoder that transforms NetworkX provenance graphs into dense embeddings
    using GraphSAGE. Purely inductive and scales dynamically to unseen entities.
    """
    def __init__(self, hidden_channels: int = 64, out_channels: int = 32):
        self.hidden_channels = hidden_channels
        self.out_channels = out_channels

        # Node type mapping (consistent with graph_builder)
        self.node_type_mapping = {'process': 0, 'file': 1, 'ip': 2, 'unknown': 3}
        
        # Features: [Type One-Hot(4)] + [In-Deg, Out-Deg, Centrality, Is-Root]
        self.num_node_features = len(self.node_type_mapping) + 4

        self.edge_type_mapping = {}
        self.num_relations = 0
        self.max_relations = 0  # Fixed capacity of the current model

        self.model = None
        self._lock = threading.Lock()
        # Tracks unknown edge types already warned about to avoid log flooding
        self._warned_edge_types: set = set()

    def _create_node_features(self, G: nx.DiGraph, node) -> torch.Tensor:
        """
        Consumes pre-calculated topological features from the NetworkX node.
        Includes Node Type (One-hot) and the 4 topological metrics.
        """
        # 1. Node Type (as index)
        n_type_str = G.nodes[node].get('type', 'unknown').lower()
        n_type_idx = self.node_type_mapping.get(n_type_str, self.node_type_mapping['unknown'])

        # 2. One-hot the type
        type_onehot = [0.0] * len(self.node_type_mapping)
        type_onehot[n_type_idx] = 1.0

        # 3. Fetch pre-calculated topological metrics [In-Deg, Out-Deg, Centrality, Is-Root]
        # Fallback to zeros if they don't exist for some reason
        topo_feats = G.nodes[node].get('features', [0.0]*5)
        
        # The node's stored 'features' already includes the type index as the first element.
        # We replace it with our dynamic one-hot vector for better neural representation.
        final_feat = type_onehot + topo_feats[1:]

        return torch.tensor(final_feat, dtype=torch.float)

    def _convert_nx_to_pyg(self, G: nx.DiGraph, is_training: bool = False) -> Data:
        """
        Converts NX graph to PyG Data using pre-calculated features.
        """
        node_mapping = {node: i for i, node in enumerate(G.nodes())}

        # Node features - Now much faster as it avoids redundant centrality calculation
        x_list = [self._create_node_features(G, node) for node in G.nodes()]
        x = torch.stack(x_list)

        # Edge indices
        edge_indices = [[], []]

        for u, v, data in G.edges(data=True):
            edge_indices[0].append(node_mapping[u])
            edge_indices[1].append(node_mapping[v])

        return Data(
            x=x, 
            edge_index=torch.tensor(edge_indices, dtype=torch.long),
            graph_id=G.graph.get('graph_id', 'unknown')
        )

    def prepare_data(self, graphs: List[nx.DiGraph], is_training: bool = False) -> List[Data]:
        """
        Converts a list of NetworkX graphs into PyG Data objects.
        During training, it builds the mapping of relations and initializes the model.
        """
        pyg_graphs = []
        for G in graphs:
            # Require at least 2 nodes. Graphs with edges=0 are still encoded — the
            # GNN conv layers simply do no message passing and pool only node features,
            # which is still meaningful for isolated-spawn or file-only anomalies.
            if G.number_of_nodes() >= 2:
                data = self._convert_nx_to_pyg(G, is_training)
                pyg_graphs.append(data)

        if is_training:
            with self._lock:
                if self.model is None:
                    # Initialize inductive SAGE model
                    self.model = GraphSAGEEncoder(
                        in_channels=self.num_node_features,
                        hidden_channels=self.hidden_channels,
                        out_channels=self.out_channels
                    )
                    logger.info(f"Initialized GraphSAGEEncoder with {self.num_node_features} node features.")
                # Explicit strict mode enforcement for training
                self.model.train()

        return pyg_graphs

    def encode(self, pyg_graphs: List[Data]) -> Tuple[torch.Tensor, List[int]]:
        """
        Passes the PyG Data objects through the GraphSAGE encoder to generate dense subgraph embeddings.
        Returns a tensor of shape [num_graphs, out_channels].
        """
        # Ensure model is initialized before encoding
        with self._lock:
            if self.model is None:
                raise ValueError("Model has not been initialized. Call prepare_data with is_training=True first.")
            model = self.model

        # Strict eval mode enforcement for inference
        model.eval() 

        embeddings_list = []
        valid_idx = []
        for i, d in enumerate(pyg_graphs):
            try:
                batch = Batch.from_data_list([d])
                with torch.no_grad():
                    e = model(batch.x, batch.edge_index, batch.batch)
                embeddings_list.append(e)
                valid_idx.append(i)
            except Exception as exc:
                logger.warning(f"Failed to encode subgraph {d.get('graph_id', 'unknown')}: {exc}")

        if not embeddings_list:
            return torch.empty(0, self.out_channels), valid_idx

        embeddings = torch.cat(embeddings_list, dim=0)
        return embeddings, valid_idx

    def extract_embeddings_with_ids(self, graphs: List[nx.DiGraph], is_training: bool = False) -> Tuple[torch.Tensor, List[str]]:
        """
        Convenience function to get embeddings and their corresponding graph IDs.
        """
        pyg_graphs = self.prepare_data(graphs, is_training=is_training)

        if not pyg_graphs:
            return torch.empty(0, self.out_channels), []

        embeddings, valid_idx = self.encode(pyg_graphs)
        graph_ids = [pyg_graphs[i].graph_id for i in valid_idx]

        return embeddings, graph_ids

    def export_model(self, path: str):
        """
        Saves the GraphSAGEEncoder weights to disk.
        """
        with self._lock:
            if self.model is None:
                logger.warning("No model to save.")
                return

            state = {
                'model_state_dict': self.model.state_dict(),
                'hidden_channels': self.hidden_channels,
                'out_channels': self.out_channels,
                'num_node_features': self.num_node_features
            }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save(state, path)
        logger.info(f"Saved GNN weights to {path}")

    def load_model_for_inference(self, path: str) -> bool:
        """
        Loads the GraphSAGEEncoder weights explicitly for inference.
        Enforces eval() mode immediately.
        """
        if not os.path.exists(path):
            logger.warning(f"GNN weights file not found: {path}")
            return False

        try:
            state = torch.load(path)
            with self._lock:
                self.hidden_channels = state['hidden_channels']
                self.out_channels = state['out_channels']
                self.num_node_features = state['num_node_features']

                # Re-initialize model with loaded parameters
                self.model = GraphSAGEEncoder(
                    in_channels=self.num_node_features,
                    hidden_channels=self.hidden_channels,
                    out_channels=self.out_channels
                )
                self.model.load_state_dict(state['model_state_dict'])
                # Strict mode enforcement
                self.model.eval()
            logger.info(f"Loaded GNN weights for inference from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load GNN weights from {path}: {e}")
            return False
