import os
import csv

chosen_sensitive_list = "sensitiveMethods.csv"


def get_chosen_sensitive_methods():
    methods = []
    with open(os.path.join("data", chosen_sensitive_list)) as f:
        reader = csv.DictReader(f)
        for row in reader:
            methods.append(row['method'])
    return methods
