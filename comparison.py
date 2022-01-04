from constants import FIELD_BENIGN_GRAPHS, FIELD_HAS_DIFFERENT_TRACES,\
    FIELD_MALIGN_GRAPHS, FIELD_METHODS, FIELD_METHODS_ONLY_BY_MALIGN


def compare_accessed_sensitive_methods(benign_paths, malign_paths):
    result = {}
    result[FIELD_BENIGN_GRAPHS] = \
        {k: v.adjacency_list for (k, v) in benign_paths.items()}
    result[FIELD_MALIGN_GRAPHS] = \
        {k: v.adjacency_list for (k, v) in malign_paths.items()}
    result[FIELD_METHODS_ONLY_BY_MALIGN] = []
    result[FIELD_METHODS] = {}
    for sensitive_method in malign_paths:
        result[FIELD_HAS_DIFFERENT_TRACES] = True
        if sensitive_method not in benign_paths:
            result[FIELD_METHODS_ONLY_BY_MALIGN].append(sensitive_method)
        else:
            malign_graph = malign_paths[sensitive_method]
            benign_graph = benign_paths[sensitive_method]
            contains_graph = benign_graph.contains_graph(malign_graph)
            result[FIELD_METHODS][sensitive_method] = contains_graph
            result[FIELD_HAS_DIFFERENT_TRACES] &= contains_graph
    return result
