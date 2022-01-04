import json
import os
from comparison import compare_accessed_sensitive_methods
from constants import FIELD_BENIGN_FILE, FIELD_MALIGN_FILE

from file import get_apps, read_logcat, read_sensitive_methods

sensitive_methods_file = "catsources.txt.final"
apps_file = "apps.csv"


def main():
    apps = get_apps(apps_file)

    result = {}
    for app_name in apps:
        benign_filename = apps[app_name][FIELD_BENIGN_FILE]
        benign_logcat_path = os.path.join("input", benign_filename)
        benign_paths = get_paths_to_sensitive_methods(benign_logcat_path)

        malign_filename = apps[app_name][FIELD_MALIGN_FILE]
        malign_logcat_path = os.path.join("input", malign_filename)
        malign_paths = get_paths_to_sensitive_methods(malign_logcat_path)

        result[app_name] =\
            compare_accessed_sensitive_methods(benign_paths, malign_paths)
        result[app_name][FIELD_BENIGN_FILE] = benign_filename
        result[app_name][FIELD_MALIGN_FILE] = malign_filename
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


if __name__ == "__main__":
    main()
