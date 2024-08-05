import yaml
import subprocess
import signal
import sys
from typing import Dict

# list for save child procceess
processes = []

def load_rules(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def run_rule_detection(script_name, rule):
    try:
        print(f"Executing {script_name} for rule: {rule['name']}...")

        rule_yaml = yaml.dump(rule)
        # create child process and save it  for terminate
        process = subprocess.Popen(['python3', script_name, rule_yaml])
        processes.append(process)
    except Exception as e:
        print(f"Error executing script {script_name}: {e}")

def terminate_processes():
    for process in processes:
        try:
            process.terminate()
        except Exception as e:
            print(f"Error terminating process: {e}")
    print("All subprocesses terminated.")

def signal_handler(sig, frame):
    print("Program is terminating, terminating subprocesses...")
    terminate_processes()
    sys.exit(0)

def main():
    # set signal manegment for terminate procces
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    print("Created By wikm with ❤️ ")
    print("Version 1.4")
    print("Starting ... ")
    print("Press Ctrl+C to stop the capture")


    rules = load_rules('rules.yaml')

    # run each rule with seprate procces
    for rule in rules['rules']:
        if rule['type'] == 'http':
            run_rule_detection('http_detect.py', rule)
        elif rule['type'] == 'tls':
            run_rule_detection('TLS.py', rule)
        elif rule['type'] == 'geosite' :
            run_rule_detection('GeoSite.py', rule)
        elif rule['type'] == 'geoip' :
            run_rule_detection('GeoIP.py', rule)
        else:
            print(f"Unknown rule type: {rule['type']}")

    # wait for end all child
    for process in processes:
        process.wait()

if __name__ == "__main__":
    main()
