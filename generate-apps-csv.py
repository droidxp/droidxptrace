import re
import csv
from os import listdir
from os.path import isfile, join

INPUT_FOLDER = 'input'


def main():
    files = [f for f in listdir(INPUT_FOLDER) if isfile(join(INPUT_FOLDER, f))]
    pattern = r'benign-app-(.*)-'

    benign_apps = []
    for file in files:
        search_result = re.search(pattern, file)
        if search_result is not None:
            app_number = search_result.group(1)
            benign_apps.append(int(app_number))
    benign_apps.sort()

    result = {}
    for number in benign_apps:
        benign_pattern = r'benign-app-' + str(number) + '-'
        malign_pattern = r'malicious-app-' + str(number) + '-'

        benign_file = None
        malign_file = None
        for file in files:
            benign_search = re.search(benign_pattern, file)
            if benign_search is not None:
                benign_file = file
            malign_search = re.search(malign_pattern, file)
            if malign_search is not None:
                malign_file = file

        if benign_file is not None \
                and malign_file is not None:
            result['app-' + str(number)] = {
                'benign': benign_file,
                'malign': malign_file,
            }

    with open('apps.csv', 'w') as f:
        writer = csv.writer(f)
        for app in result:
            row = [app, result[app]['benign'], result[app]['malign']]
            writer.writerow(row)
    print("app.csv created with success!")


if __name__ == "__main__":
    main()
