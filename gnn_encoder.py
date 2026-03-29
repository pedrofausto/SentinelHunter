import torch
import torch.nn.functional as F
from torch_geometric.nn import RGCNConv, global_mean_pool
from torch_geometric.data import Data, Batch
import networkx as nx
from typing import List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)

class RGCNEncoder(torch.nn.Module):
    """
    Relational Graph Convolutional Network (RGCN) implemented with PyTorch Geometric.
    Focuses on processing the Provenance Graph based strictly on relationships
    and edge types, avoiding fragile textual attributes (like IPs or file names).
    """
    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int, num_relations: int):
        super().__init__()
        # RGCN Convolution layers to learn node representations considering relation types
        self.conv1 = RGCNConv(in_channels, hidden_channels, num_relations)
        self.conv2 = RGCNConv(hidden_channels, hidden_channels, num_relations)

        # We output a subgraph embedding by pooling the learned node features
        # and feeding them into an MLP.
        self.lin = torch.nn.Linear(hidden_channels, out_channels)

    def forward(self, x, edge_index, edge_type, batch):
        # x: Node features [num_nodes, in_channels]
        # edge_index: Graph connectivity [2, num_edges]
        # edge_type: Edge relation types [num_edges]
        # batch: Batch vector [num_nodes]

        # First GNN layer
        x = self.conv1(x, edge_index, edge_type)
        x = F.relu(x)
        x = F.dropout(x, p=0.2, training=self.training)

        # Second GNN layer
        x = self.conv2(x, edge_index, edge_type)
        x = F.relu(x)

        # Pooling to obtain a subgraph representation vector (dense embedding)
        # We aggregate all node features in each graph into a single vector
        x = global_mean_pool(x, batch)

        # Final linear layer to produce the embedding
        x = self.lin(x)
        return x

class TopologicalGraphEncoder:
    """
    Module responsible for converting NetworkX Directed Provenance Graphs
    into PyTorch Geometric Data objects and producing dense embeddings using RGCN.
    """
    def __init__(self, hidden_channels: int = 64, out_channels: int = 32):
        self.hidden_channels = hidden_channels
        self.out_channels = out_channels

        # Mappings to translate categorical data to numeric representations (topological focus)
        # One-hot encoding for node types (Process, File, IP)
        self.node_type_mapping = {'process': 0, 'file': 1, 'ip': 2, 'unknown': 3}
        self.num_node_features = len(self.node_type_mapping) + 2 # +2 for in-degree, out-degree

        # We will learn the edge types dynamically as we see them, or use a predefined set
        self.edge_type_mapping = {}
        self.num_relations = 0

        self.model = None # Initialized after relation types are gathered

    def _create_node_features(self, G: nx.DiGraph, node) -> torch.Tensor:
        """
        Creates mathematical/topological features for a node:
        [One-hot Type, In-Degree, Out-Degree]
        This ignores fragile IoC strings.
        """
        n_type_str = G.nodes[node].get('type', 'unknown').lower()
        n_type_idx = self.node_type_mapping.get(n_type_str, self.node_type_mapping['unknown'])

        # One-hot vector for node type
        feat = [0.0] * len(self.node_type_mapping)
        feat[n_type_idx] = 1.0

        # Topological metrics
        feat.append(float(G.in_degree(node)))
        feat.append(float(G.out_degree(node)))

        return torch.tensor(feat, dtype=torch.float)

    def _convert_nx_to_pyg(self, G: nx.DiGraph, is_training: bool = False) -> Data:
        """
        Converts a NetworkX DiGraph to a PyTorch Geometric Data object.
        """
        # Node mapping: string name -> integer index
        node_mapping = {node: i for i, node in enumerate(G.nodes())}

        # Prepare node features
        x_list = []
        for node in G.nodes():
            x_list.append(self._create_node_features(G, node))
        x = torch.stack(x_list)

        # Prepare edge indices and types
        edge_indices = [[], []]
        edge_types = []

        for u, v, data in G.edges(data=True):
            edge_indices[0].append(node_mapping[u])
            edge_indices[1].append(node_mapping[v])

            # Handle edge types
            action = data.get('action', 'unknown').lower()
            if is_training and action not in self.edge_type_mapping:
                self.edge_type_mapping[action] = self.num_relations
                self.num_relations += 1

            e_type = self.edge_type_mapping.get(action, 0) # default to 0 if unseen
            edge_types.append(e_type)

        edge_index = torch.tensor(edge_indices, dtype=torch.long)
        edge_type = torch.tensor(edge_types, dtype=torch.long)

        # Return PyG Data object
        return Data(x=x, edge_index=edge_index, edge_type=edge_type, graph_id=G.graph.get('graph_id', 'unknown'))

    def prepare_data(self, graphs: List[nx.DiGraph], is_training: bool = False) -> List[Data]:
        """
        Converts a list of NetworkX graphs into PyG Data objects.
        During training, it builds the mapping of relations.
        """
        pyg_graphs = []
        for G in graphs:
            if G.number_of_nodes() > 0:
                data = self._convert_nx_to_pyg(G, is_training)
                pyg_graphs.append(data)

        if is_training and self.model is None:
            # Initialize model now that we know num_relations
            # Ensure at least 1 relation to avoid errors in RGCNConv
            num_rels = max(1, self.num_relations)
            self.model = RGCNEncoder(
                in_channels=self.num_node_features,
                hidden_channels=self.hidden_channels,
                out_channels=self.out_channels,
                num_relations=num_rels
            )
            logger.info(f"Initialized RGCNEncoder with {self.num_node_features} node features and {num_rels} relations.")

        return pyg_graphs

    def encode(self, pyg_graphs: List[Data]) -> torch.Tensor:
        """
        Passes the PyG Data objects through the RGCN to generate dense subgraph embeddings.
        Returns a tensor of shape [num_graphs, out_channels].
        """
        if self.model is None:
            raise ValueError("Model has not been initialized. Call prepare_data with is_training=True first.")

        self.model.eval() # We use the encoder primarily for inference/feature extraction

        # Batching multiple graphs together for efficient processing
        batch = Batch.from_data_list(pyg_graphs)

        with torch.no_grad():
            embeddings = self.model(batch.x, batch.edge_index, batch.edge_type, batch.batch)

        return embeddings

    def extract_embeddings_with_ids(self, graphs: List[nx.DiGraph], is_training: bool = False) -> Tuple[torch.Tensor, List[str]]:
        """
        Convenience function to get embeddings and their corresponding graph IDs.
        """
        pyg_graphs = self.prepare_data(graphs, is_training=is_training)

        if not pyg_graphs:
            return torch.empty(0, self.out_channels), []

        embeddings = self.encode(pyg_graphs)
        graph_ids = [data.graph_id for data in pyg_graphs]

        return embeddings, graph_ids
