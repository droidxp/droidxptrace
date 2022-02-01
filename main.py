import json
import os
from comparison import compare_accessed_sensitive_methods
from constants import FIELD_APPS, FIELD_BENIGN_FILE, FIELD_MALIGN_FILE, \
    FIELD_METHODS_ONLY_BY_MALIGN, FIELD_RANKING, FIELD_BENIGN_GRAPHS, \
    FIELD_MALIGN_GRAPHS, FIELD_DISTANCES_BENIGN, FIELD_DISTANCES_MALIGN, \
    FIELD_DISTANCES_ONLY_MALIGN, BENIGN_METHODS, MALIGN_METHODS, \
    ONLY_MALIGN_METHODS

from file import get_apps, read_logcat, read_sensitive_methods
from utils import get_chosen_sensitive_methods

sensitive_methods_file = "catsources.txt.final"
apps_file = "apps.csv"


def main():
    apps = get_apps(apps_file)

    result = {}
    result[FIELD_APPS] = {}
    for app_name in apps:
        benign_filename = apps[app_name][FIELD_BENIGN_FILE]
        benign_logcat_path = os.path.join("input", benign_filename)
        benign_paths = get_paths_to_sensitive_methods(benign_logcat_path)

        malign_filename = apps[app_name][FIELD_MALIGN_FILE]
        malign_logcat_path = os.path.join("input", malign_filename)
        malign_paths = get_paths_to_sensitive_methods(malign_logcat_path)

        result[FIELD_APPS][app_name] =\
            compare_accessed_sensitive_methods(benign_paths, malign_paths)
        result[FIELD_APPS][app_name][FIELD_BENIGN_FILE] = benign_filename
        result[FIELD_APPS][app_name][FIELD_MALIGN_FILE] = malign_filename
    # Ranking of sensitive methods
    result[FIELD_RANKING] = get_ranking_sensitive_methods(result[FIELD_APPS])
    # Relation between min distance to sensitive methods and apps
    result[FIELD_DISTANCES_BENIGN] = get_distances(result, BENIGN_METHODS)
    result[FIELD_DISTANCES_MALIGN] = get_distances(result, MALIGN_METHODS)
    result[FIELD_DISTANCES_ONLY_MALIGN] = get_distances(
        result, ONLY_MALIGN_METHODS)
    print(json.dumps(result))


def get_distances(result, base=BENIGN_METHODS):
    chosen_methods = get_chosen_sensitive_methods()

    distances = {}
    for app_name in result[FIELD_APPS]:
        if base is BENIGN_METHODS:
            graph = result[FIELD_APPS][app_name][FIELD_BENIGN_GRAPHS]
            methods = graph.keys()
        elif base is MALIGN_METHODS:
            graph = result[FIELD_APPS][app_name][FIELD_MALIGN_GRAPHS]
            methods = graph.keys()
        elif base is ONLY_MALIGN_METHODS:
            graph = result[FIELD_APPS][app_name][FIELD_MALIGN_GRAPHS]
            methods = result[FIELD_APPS][app_name][FIELD_METHODS_ONLY_BY_MALIGN]
        distances[app_name] = []
        for sensitive_method in chosen_methods:
            if sensitive_method in methods:
                distance = get_minimum_distance_to_entrypoint(
                    graph, sensitive_method)
                distances[app_name].append(distance)
            else:
                distances[app_name].append(None)
    return distances


def get_minimum_distance_to_entrypoint(graphs, sensitive_method):
    graph = graphs[sensitive_method]
    return get_minimum_distance_to_entrypoint_helper(graph, sensitive_method, 0)


def get_minimum_distance_to_entrypoint_helper(graph, method, distance):
    if method not in graph:
        return distance

    min_distance = float('inf')
    for edge in graph[method]:
        distance = get_minimum_distance_to_entrypoint_helper(
            graph, edge, distance + 1)
        min_distance = min(min_distance, distance)

    return min_distance


def get_paths_to_sensitive_methods(logcat_path):
    call_graph = read_logcat(logcat_path)
    transposed_graph = call_graph.generate_transpose_graph()

    sensitive_methods_path = os.path.join("data", sensitive_methods_file)
    sensitive_methods = read_sensitive_methods(sensitive_methods_path)

    paths = {}
    for method in transposed_graph.get_nodes():
        if method in sensitive_methods:
            paths[method] = transposed_graph.get_subgraph_from(method)
    return paths


def get_ranking_sensitive_methods(result):
    freq = {}
    for app_name in result:
        methods = result[app_name][FIELD_METHODS_ONLY_BY_MALIGN]
        for method in methods:
            if method not in freq:
                freq[method] = 0
            freq[method] += 1
    methods = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    ranking = []
    for method in methods:
        ranking.append({"method": method[0], "freq": method[1]})
    return ranking


if __name__ == "__main__":
    main()
