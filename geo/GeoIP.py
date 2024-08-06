from scapy.all import sniff, IP , TCP , Raw
import yaml
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from settings.telegram import send_to_telegram
import ipaddress
import subprocess
import signal
import json
import time

def add_iptables_rule(ip, port , transport , configs):
    if transport == "all" :
        #Block outbound
        iptable_rule = f"-A OUTPUT -d {ip} -j DROP"
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
        iptable_rule = f"-A INPUT -s {ip} -j DROP"
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
    else :
        #Block outbound
        iptable_rule = f"-A OUTPUT -p {transport} -d {ip} --dport {port} -j DROP"
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
        iptable_rule = f"-A INPUT -p {transport} -s {ip} --sport {port} -j DROP"
        if configs['core']['rule_type'] == 'hierarchy':
            # read iptable rules json
            with open('iptable.json', 'r') as file:
                iptable_rules_json = json.load(file)
            # add rule 
            iptable_rules_json.append(iptable_rule)
            # save rules to json
            with open('iptable.json', 'w') as file:
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

def ip_in_set(ip_set, target_ip):
    return target_ip in ip_set

def list_ips(ip_range):
    network = ipaddress.ip_network(ip_range)
    return [str(ip) for ip in network.hosts()]

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def handle_packet(packet , rule , configs , ips , transport):
    #print(type(packet[IP.dst]))
    if packet.haslayer(IP):
        target = packet[IP].dst
        if ip_in_set(ips , target):
            if rule['action'] == "check" or rule['action'] == "block" :
                mess = f"[Detected] Packet to {packet[IP].dst} from {packet[IP].src}"
                print(mess)
                try :
                    send_to_telegram(mess)
                except Exception as e:
                    print(f"An error has ocuured : {e}")
                target = ""
                if rule['action'] == "block" :
                    if packet.haslayer(IP) and packet.haslayer(TCP):
                        if Raw in packet:
                            add_iptables_rule(packet[IP].dst, packet[TCP].dport , transport , configs)
                    else :
                        transport = "all"
                        add_iptables_rule(packet[IP].dst, "None" , transport , configs) 

def geoip_packet_callback(packet):
    handle_packet(packet  , rule , configs , ips , transport)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No rule data provided.")
    rule_yaml = sys.argv[1]

    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        print("Failed to decode YAML.")
    configs = load_yaml('./settings/config.yaml')
    path = configs['path']['geoip']

    ip_ranges = []
    ips = set()
    with open (path  , "r") as f:
        for line in f :
            range = line.strip()
            ip_ranges.append(range)

    print(f"Monitoring traffic to {ip_ranges}")

    for ip_range in ip_ranges:
        temp = []
        temp = list_ips(ip_range)
        ips.update(temp)
    
    transport = rule['transport']
    iptable_rules = []
    def signal_handler(sig, frame):
        cleanup_iptables(iptable_rules)
        sys.stdout.write("Cleaning up iptables rules...")
        time.sleep(2)
        sys.exit(0)
        time.sleep(2)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    sniff(filter="ip", prn=geoip_packet_callback)