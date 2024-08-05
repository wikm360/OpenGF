from scapy.all import sniff, DNS, DNSQR, DNSRR, IP , TCP
import yaml
import sys
from typing import Dict
from telegram import send_to_telegram
import signal
import subprocess

def add_iptables_rule(ip, port):
    if port == "None" :
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
        iptable_rule = f"-A OUTPUT -p tcp -d {ip} --dport {port} -j DROP"
        iptable_rules.append(iptable_rule)
        subprocess.run(["sudo", "iptables", *iptable_rule.split()])
        #block inbound
        iptable_rule = f"-A INPUT -p tcp -s {ip} --sport {port} -j DROP"
        iptable_rules.append(iptable_rule)
        subprocess.run(["sudo", "iptables", *iptable_rule.split()])
        mess = f"BLOCKED: {ip}"
        print(mess)
        send_to_telegram(mess)

def cleanup_iptables(rules):
    for rule in rules:
        rule = "-D" + rule[2:]
        subprocess.run(["sudo", "iptables", *rule.split()])


def load_yaml(file_path: str) -> Dict:
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def handle_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qdcount > 0:
        qname = packet[DNSQR].qname.decode()[:-1]
        if qname.startswith("www.") :
            qname = qname[4:]
        if qname in domains:
            if packet[DNS].ancount > 0:
                for i in range(packet[DNS].ancount):
                    rr = packet[DNSRR][i]
                    if rr.type == 1:  # A record
                        domains[qname].append(rr.rdata)
                        mess = f"[DNS Response] {qname} -> {rr.rdata} (IPv4)"
                        print(mess)
                        send_to_telegram(mess)
                    elif rr.type == 28:  # AAAA record
                        domains[qname].append(rr.rdata)
                        mess = f"[DNS Response] {qname} -> {rr.rdata} (IPv6)"
                        print(mess)
                        send_to_telegram(mess)

def handle_packet(packet):
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst
        for key , value in domains.items() :
            if packet[IP].dst in value:
                if rule['action'] == 'check' or rule['action'] == 'block' :
                    mess = f"[Detected] Packet to {packet[IP].dst} from {packet[IP].src}"
                    print(mess)
                    send_to_telegram(mess)
                    if rule['action'] == 'block':
                        if TCP in packet :
                            dst_port  = packet[TCP].dport
                            add_iptables_rule(dst_ip, dst_port)
                        else :
                            add_iptables_rule(dst_ip, "None")

def packet_callback(packet):
    if packet.haslayer(DNS):
        handle_dns(packet)
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

    domains = {}
    with open (path  , "r") as f:
        for line in f :
            domain = line.strip()
            domains[domain] = []


    print(f"Monitoring traffic to {domains}")

    iptable_rules = []
    def signal_handler(sig, frame):
        cleanup_iptables(iptable_rules)
        print("Cleaning up iptables rules...")
        sys.exit(0)

    def signal_handler(sig, frame):
        cleanup_iptables(iptable_rules)
        print("Cleaning up iptables rules...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    sniff(filter="ip", prn=packet_callback)
