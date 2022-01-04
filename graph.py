import json


class Graph(object):

    def __init__(self) -> None:
        self._adjacency_list = {}

    @property
    def adjacency_list(self):
        return self._adjacency_list

    def add_graph_edge(self, src, dest) -> None:
        if src not in self._adjacency_list:
            self._adjacency_list[src] = []
        if dest not in self._adjacency_list[src]:
            self._adjacency_list[src].append(dest)

    def generate_transpose_graph(self):
        transposed_graph = Graph()
        for caller in self._adjacency_list:
            for callee in self._adjacency_list[caller]:
                transposed_graph.add_graph_edge(callee, caller)
        return transposed_graph

    def get_subgraph_from(self, root):
        if root not in self._adjacency_list:
            return None
        subgraph = Graph()

        visited = {}
        queue = []
        queue.append(root)
        visited[root] = True
        while queue:
            caller_node = queue.pop()
            if caller_node in self._adjacency_list:
                for callee_node in self._adjacency_list[caller_node]:
                    if callee_node not in visited \
                            or not visited[callee_node]:
                        subgraph.add_graph_edge(caller_node, callee_node)
                        queue.append(callee_node)
                        visited[callee_node] = True
        return subgraph

    def get_nodes(self):
        nodes = []
        for node in self._adjacency_list:
            nodes.append(node)
        return nodes

    def contains_graph(self, second_graph):
        for element in second_graph.adjacency_list:
            if element not in self._adjacency_list:
                return False
            else:
                for e in second_graph.adjacency_list[element]:
                    if e not in self._adjacency_list[element]:
                        return False
        return True

    def to_json(self):
        return json.dumps(self._adjacency_list)
