from audioop import reverse
import json
import os
from comparison import compare_accessed_sensitive_methods
from constants import FIELD_APPS, FIELD_BENIGN_FILE, FIELD_MALIGN_FILE, FIELD_METHODS_ONLY_BY_MALIGN, FIELD_RANKING

from file import get_apps, read_logcat, read_sensitive_methods

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
    print(json.dumps(result))


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
