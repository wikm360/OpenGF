from scapy.all import sniff, IP , send , TCP , Raw
import yaml
import sys
from telegram import send_to_telegram
import ipaddress
import subprocess
import signal

def add_iptables_rule(ip, port):
    if transport == "all" :
        #Block outbound
        iptable_rule = f"-A OUTPUT -d {ip} -j DROP"
        iptable_rules.append(iptable_rule)
        subprocess.run(["sudo", "iptables", *iptable_rule.split()])
        #block inbound
        iptable_rule = f"-A INPUT -s {ip} -j DROP"
        iptable_rules.append(iptable_rule)
        subprocess.run(["sudo", "iptables", *iptable_rule.split()])
        mess = f"BLOCKED: {ip}"
        print(mess)
        send_to_telegram(mess)
    else :
        #Block outbound
        iptable_rule = f"-A OUTPUT -p {transport} -d {ip} --dport {port} -j DROP"
        iptable_rules.append(iptable_rule)
        subprocess.run(["sudo", "iptables", *iptable_rule.split()])
        #block inbound
        iptable_rule = f"-A INPUT -p {transport} -s {ip} --sport {port} -j DROP"
        iptable_rules.append(iptable_rule)
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

def handle_packet(packet):
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
                            add_iptables_rule(packet[IP].dst, packet[TCP].dport)

def packet_callback(packet):
    handle_packet(packet)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No rule data provided.")
    rule_yaml = sys.argv[1]

    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        print("Failed to decode YAML.")
    path = rule['path']
    configs = load_yaml('config.yaml')

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
        print("Cleaning up iptables rules...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    sniff(filter="ip", prn=packet_callback)