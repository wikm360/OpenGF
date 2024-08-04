from scapy.all import sniff, DNS, DNSQR, DNSRR, IP
import yaml
import sys
from typing import Dict

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
                        print(f"[DNS Response] {qname} -> {rr.rdata} (IPv4)")
                    elif rr.type == 28:  # AAAA record
                        domains[qname].append(rr.rdata)
                        print(f"[DNS Response] {qname} -> {rr.rdata} (IPv6)")

def handle_packet(packet):
    if packet.haslayer(IP):
        for key , value in domains.items() :
            if packet[IP].dst in value:
                print(f"[Detected] Packet to {packet[IP].dst} from {packet[IP].src}")

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

    sniff(filter="ip", prn=packet_callback)
