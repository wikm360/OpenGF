import signal
import sys
import subprocess
import yaml
import time

processes = []

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def run_rule_detection(script_name , coretype):
    try:
        print(f"Run as {coretype} Rule ...")

        process = subprocess.Popen(['python3', script_name])
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
    time.sleep(2)
    sys.exit(0)
    time.sleep(2)

def main():
    # set signal manegment for terminate procces
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    print("Created By wikm with ❤️ ")
    print("Version 2.0")
    print("Starting ... ")
    print("Press Ctrl+C to stop the capture")


    coretype = load_yaml('./settings/config.yaml')['core']['rule_type']

    if coretype == 'hierarchy':
        run_rule_detection('Hierarchy.py' , coretype)
    elif coretype == 'parallel':
        run_rule_detection('Parallel.py' , coretype)
    else:
        print(f"Unknown core rule_type")

    # wait for end all child
    for process in processes:
        process.wait()

if __name__ == "__main__":
    main()
