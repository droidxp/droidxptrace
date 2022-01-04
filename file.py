import re
import csv
from constants import FIELD_BENIGN_FILE, FIELD_MALIGN_FILE
from graph import Graph


def read_sensitive_methods(file_path):
    sensitive_methods = {}
    with open(file_path) as f:
        lines = f.readlines()
        for line in lines:
            pattern = r'<(.+)> \((.+)\)'
            search_result = re.search(pattern, line)
            method = search_result.group(1) \
                if search_result is not None else None
            category = search_result.group(2) \
                if search_result is not None else None
            if method and category:
                sensitive_methods[method] = category
    return sensitive_methods


def read_logcat(file_path):
    call_graph = Graph()
    with open(file_path) as f:
        lines = f.readlines()
        for line in lines:
            if " -> " in line:
                pattern = r'<(.+)> -> <(.+)>'
                search_result = re.search(pattern, line)
                caller = search_result.group(1) \
                    if search_result is not None else None
                callee = search_result.group(2) \
                    if search_result is not None else None
                if caller and callee:
                    call_graph.add_graph_edge(caller, callee)
    return call_graph


def get_apps(apps_file):
    apps = {}
    with open(apps_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) == 3:
                app_name = row[0].strip()
                apps[app_name] = {
                    FIELD_BENIGN_FILE: row[1].strip(),
                    FIELD_MALIGN_FILE: row[2].strip(),
                }
    return apps
