from asyncore import file_wrapper
import csv
import sys
import os
import json
from constants import FIELD_DISTANCES_ONLY_MALIGN

from utils import get_chosen_sensitive_methods

output_file = 'output.csv'


def main(file_path):
    if not os.path.isfile(file_path):
        print(f"The provided file does not exist: {file_path}")
        return
    with open(file_path, 'r') as f:
        result_json = json.loads(f.read())
        methods = get_chosen_sensitive_methods()
        with open(output_file, 'w', newline='') as csv_file:
            fields = ['apps'] + methods
            writer = csv.DictWriter(
                csv_file, fieldnames=fields, dialect='excel')
            writer.writeheader()

            for app_name in result_json[FIELD_DISTANCES_ONLY_MALIGN]:
                row = {'apps': app_name}
                for idx, method_name in enumerate(methods):
                    row[method_name] = \
                        result_json[FIELD_DISTANCES_ONLY_MALIGN][app_name][idx]
                writer.writerow(row)


if __name__ == '__main__':
    if (len(sys.argv) <= 1):
        print("Not enough arguments were provided.\n"
              "Please execute the command in the following way:\n\n"
              "\tpython3 generate-distances-csv.py <file>")
    else:
        file_path = sys.argv[1]
        main(file_path)
