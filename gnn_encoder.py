import os
import torch
import torch.nn.functional as F
from torch_geometric.nn import RGATConv, global_mean_pool, global_max_pool
import networkx as nx
from typing import List, Dict, Any, Tuple
import logging
import threading

from torch_geometric.data import Data, Batch

logger = logging.getLogger(__name__)

class RGATEncoder(torch.nn.Module):
    """
    Relational Graph Attention Network (RGAT).
    Uses multi-head attention to learn which node relationships are most 
    critical for identifying malicious intent.
    """
    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int, num_relations: int):
        super().__init__()
        # Layer 1: Relational Attention
        self.conv1 = RGATConv(in_channels, hidden_channels, num_relations, heads=4, concat=True)
        # Layer 2: Relational Attention with Residual
        self.conv2 = RGATConv(hidden_channels * 4, hidden_channels, num_relations, heads=4, concat=False)
        
        # Linear layers for pooling and final embedding
        self.lin1 = torch.nn.Linear(hidden_channels, hidden_channels)
        self.lin2 = torch.nn.Linear(hidden_channels, out_channels)

    def forward(self, x, edge_index, edge_type, batch):
        # Initial convolution
        x1 = self.conv1(x, edge_index, edge_type)
        x1 = F.elu(x1)
        x1 = F.dropout(x1, p=0.2, training=self.training)

        # Second convolution with Attention
        x2 = self.conv2(x1, edge_index, edge_type)
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
    using Relational Graph Attention. Focuses on structural importance (centrality, degree).
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

        # Edge indices and types
        edge_indices = [[], []]
        edge_types = []

        for u, v, data in G.edges(data=True):
            edge_indices[0].append(node_mapping[u])
            edge_indices[1].append(node_mapping[v])

            action = data.get('action', 'unknown').lower()
            with self._lock:
                if is_training and action not in self.edge_type_mapping:
                    self.edge_type_mapping[action] = self.num_relations
                    self.num_relations += 1
                e_type = self.edge_type_mapping.get(action, 0)
                
                # Cap edge_type to the model's capacity to avoid IndexError.
                # Log a warning once per unknown type so operators know retraining may help.
                if self.max_relations > 0 and e_type >= self.max_relations:
                    if action not in self._warned_edge_types:
                        logger.warning(
                            f"[GNN] Unknown edge type '{action}' (index {e_type}) exceeds model "
                            f"capacity ({self.max_relations} relations). Mapping to relation 0. "
                            "Retraining is recommended if this type appears frequently."
                        )
                        self._warned_edge_types.add(action)
                    e_type = 0

            edge_types.append(e_type)

        return Data(
            x=x, 
            edge_index=torch.tensor(edge_indices, dtype=torch.long),
            edge_type=torch.tensor(edge_types, dtype=torch.long),
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
                    # Initialize model now that we know num_relations
                    # Ensure at least 1 relation to avoid errors in RGATConv
                    self.max_relations = max(1, self.num_relations)
                    self.model = RGATEncoder(
                        in_channels=self.num_node_features,
                        hidden_channels=self.hidden_channels,
                        out_channels=self.out_channels,
                        num_relations=self.max_relations
                    )
                    logger.info(f"Initialized RGATEncoder with {self.num_node_features} node features and {self.max_relations} relations.")

        return pyg_graphs

    def encode(self, pyg_graphs: List[Data]) -> Tuple[torch.Tensor, List[int]]:
        """
        Passes the PyG Data objects through the RGCN to generate dense subgraph embeddings.
        Returns a tensor of shape [num_graphs, out_channels].
        """
        # Ensure model is initialized before encoding
        with self._lock:
            if self.model is None:
                raise ValueError("Model has not been initialized. Call prepare_data with is_training=True first.")
            model = self.model

        model.eval() # We use the encoder primarily for inference/feature extraction

        embeddings_list = []
        valid_idx = []
        for i, d in enumerate(pyg_graphs):
            try:
                batch = Batch.from_data_list([d])
                with torch.no_grad():
                    e = model(batch.x, batch.edge_index, batch.edge_type, batch.batch)
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

    def save(self, path: str):
        """
        Saves the RGATEncoder weights and relation mapping to disk.
        """
        with self._lock:
            if self.model is None:
                logger.warning("No model to save.")
                return

            state = {
                'model_state_dict': self.model.state_dict(),
                'edge_type_mapping': self.edge_type_mapping,
                'num_relations': self.num_relations,
                'max_relations': self.max_relations,
                'hidden_channels': self.hidden_channels,
                'out_channels': self.out_channels,
                'num_node_features': self.num_node_features
            }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save(state, path)
        logger.info(f"Saved GNN weights to {path}")

    def load(self, path: str):
        """
        Loads the RGATEncoder weights and relation mapping from disk.
        """
        if not os.path.exists(path):
            logger.warning(f"GNN weights file not found: {path}")
            return False

        try:
            state = torch.load(path)
            with self._lock:
                self.edge_type_mapping = state['edge_type_mapping']
                self.num_relations = state['num_relations']
                self.max_relations = state.get('max_relations', state['num_relations'])
                self.hidden_channels = state['hidden_channels']
                self.out_channels = state['out_channels']
                self.num_node_features = state['num_node_features']

                # Re-initialize model with loaded parameters
                self.model = RGATEncoder(
                    in_channels=self.num_node_features,
                    hidden_channels=self.hidden_channels,
                    out_channels=self.out_channels,
                    num_relations=max(1, self.max_relations)
                )
                self.model.load_state_dict(state['model_state_dict'])
            logger.info(f"Loaded GNN weights from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load GNN weights from {path}: {e}")
            return False
