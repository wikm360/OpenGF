from scapy.all import sniff, TCP , IP
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from settings.telegram import send_to_telegram
import signal
import yaml
import subprocess
import json
import time

def log_traffic(src_ip, src_port , dst_ip , dst_port , packet , type_check):
    mess = f"SSH Packet Matched by {type_check} / Source: {src_ip}:{src_port} / Destination: {dst_ip}:{dst_port} / / packet: [ {packet.summary()}  ] ..."
    print(mess)
    print("--------------------")
    send_to_telegram(mess)

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def add_iptables_rule(ip, port , configs):
    if not port :
        port = 22
#Block outbound
    iptable_rule = f"-A OUTPUT -p tcp -d {ip} --dport {port} -j DROP"
    if configs['core']['rule_type'] == 'hierarchy':
        # read iptable rules json
        with open('./settings/iptable.json', 'r') as file:
            iptable_rules_json = json.load(file)
        # add rule 
        iptable_rules_json.append(iptable_rule)
        # save rules to json
        with open('./settings/iptable.json', 'w') as file:
            json.dump(iptable_rules_json, file)
    else :
        iptable_rules.append(iptable_rule)
    #run block outblound:
    subprocess.run(["sudo", "iptables", *iptable_rule.split()])

    #block inbound
    iptable_rule = f"-A INPUT -p tcp -s {ip} --sport {port} -j DROP"
    if configs['core']['rule_type'] == 'hierarchy':
        # read iptable rules json
        with open('./settings/iptable.json', 'r') as file:
            iptable_rules_json = json.load(file)
        # add rule 
        iptable_rules_json.append(iptable_rule)
        # save rules to json
        with open('./settings/iptable.json', 'w') as file:
            json.dump(iptable_rules_json, file)
    else :
        iptable_rules.append(iptable_rule)
    #run block inbound
    subprocess.run(["sudo", "iptables", *iptable_rule.split()])
    
    mess = f"BLOCKED: {ip}"
    print(mess)
    send_to_telegram(mess)

def cleanup_iptables(rules):
    for rule in rules:
        rule = "-D" + rule[2:]
        subprocess.run(["sudo", "iptables", *rule.split()])


def is_ssh_packet(packet):
    SSH_PATTERN = re.compile(rb'^SSH-\d\.\d+-')
    if packet.haslayer(TCP):
        payload = bytes(packet[TCP].payload)
        if SSH_PATTERN.match(payload):
            return True
    return False

def packet_callback (packet) :
    analyze_ssh(packet=packet , rule=rule , configs=configs)

def analyze_ssh(packet , rule , configs ):

    if is_ssh_packet(packet):
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        if rule['action'] == 'check' or rule['action'] == 'block':
            if rule['ip'] == "all" :
                log_traffic(src_ip, src_port , dst_ip , dst_port , packet , rule['ip'])
                if rule['action'] == 'block':
                    add_iptables_rule(dst_ip,dst_port, configs)
            elif rule['ip'] == dst_ip  :
                log_traffic(src_ip, src_port , dst_ip , dst_port , packet , 'ip')
                if rule['action'] == 'block':
                    add_iptables_rule(dst_ip,dst_port, configs)

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("No rule data provided.")
    rule_yaml = sys.argv[1]
    
    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        print("Failed to decode YAML.")

    configs = load_yaml('./settings/config.yaml')
    interface = configs['io']['interface']

    iptable_rules = []
    def signal_handler(sig, frame):
        cleanup_iptables(iptable_rules)
        sys.stdout.write("Cleaning up iptables rules...")
        time.sleep(2)
        sys.exit(0)
        time.sleep(2)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    filter_str = "tcp"
    if interface == "all" :
        sniff(filter=filter_str, prn=packet_callback, store=0)
    else :
        sniff(iface=interface , filter=filter_str, prn=packet_callback, store=0)

