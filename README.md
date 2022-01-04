# Trace Extractor for DroidXP's Logs
This projects will extract information about the dynamic callgraph logged by logcat during the execution of DroidXP [benchmark](https://github.com/droidxp/benchmark).

## How to execute
To run this project, you just need to execute the following command:
```
    python3 main.py > output.json
```

The program will output the file `output.json` with the result of the extraction.

## How to add new inputs
The log file provided by logcat must be stored at `input/` folder. You should provide the execution log for the two versions of the app: benign and malign.

Besides, you should provide the names of the log files in the `apps.csv` file in the following format:

```csv
<app_identifier>,<benign_logcat>,<malign_logcat>
```

## Results format

This program will output a JSON file containing the following information:

- App identifier:
    - `benign`: The name of the log file of the benign version of the app
    - `malign`: The name of the log file of the malign version of the app
    - `benignGraphs`: The benign's sub-callgraphs filtered that containing the all traces that access a sensitive methods
    - `malignGraphs`: The malign's sub-callgraphs filtered that containing the all traces that access a sensitive methods
    - `methodsAccessedOnlyByMalign`: The sensitive methods accessed only the malign version of the app. This information is important to identify if malign version breaks the sandbox
    - `benignGraphContainsMalignGraph`: Comparison between benign and malign's sub-callgraphs
    - `hasDifferentTraces`: information about malign and benign has different traces

The file [output.example.json](./output.example.json) contains an example of output.
