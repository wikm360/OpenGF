import sys
import subprocess
import json
import time



def signal_handler(sig, frame):
    # read iptable rulesjson
    with open('iptable.json', 'r') as file:
        iptable_rules = json.load(file)
    
    print(iptable_rules)
    cleanup_iptables(iptable_rules)
    print("Cleaning up iptables rules...")
    time.sleep(2)
    sys.exit(0)
    time.sleep(2)
    

def cleanup_iptables(iptable_rules):
    for rule in iptable_rules:
        print(rule)
        rule = "-D" + rule[2:]
        subprocess.run(["sudo", "iptables", *rule.split()])
    #delete iptable json file
    with open('iptable.json', 'w') as file:
        iptable_rules.clear()
        json.dump(iptable_rules, file)
    