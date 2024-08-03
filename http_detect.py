import yaml
from scapy.all import sniff, IP, TCP, Raw
import re
from typing import Dict
from threading import Thread
import sys

class HTTPAnalyzer:
    def __init__(self, rule: Dict):
        self.rule = rule
        self.http_pattern = re.compile(rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT) .+ HTTP/\d\.\d')

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet and Raw in packet:
            src_port = packet[TCP].sport
            dst_port  = packet[TCP].dport
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload = bytes(packet[Raw])

            # http detect :
            if self.is_http(payload):
                # get host :
                host = "None"
                host_pattern = re.compile(rb'Host: (.+?)\r\n')
                match = host_pattern.search(payload)
                # match rules with http packet 
                if match:
                    host = match.group(1).decode()
                if self.rule['type'] == 'http' and (src_ip == self.rule['ip'] or dst_ip == self.rule['ip']) and self.check_host(payload):
                    self.log_traffic(src_ip, dst_ip, payload , host , "ip and host")
                elif self.rule['type'] == 'http' and (src_ip == self.rule['ip'] or dst_ip == self.rule['ip']):
                    self.log_traffic(src_ip, dst_ip, payload , host , "ip")
                elif self.rule['type'] == 'http' and self.check_host(payload):
                    self.log_traffic(src_ip, dst_ip, payload , host , "host")

    def is_http(self, payload: bytes) -> bool:
        return bool(self.http_pattern.match(payload))

    def check_host(self, payload: bytes) -> bool:
        # check rule host with host header
        host_pattern = re.compile(rb'Host: (.+?)\r\n')
        match = host_pattern.search(payload)
        if match:
            host = match.group(1).decode()
            return host == self.rule['host']
        return False

    def log_traffic(self, src_ip, dst_ip, payload , host , type_check):
        print(f"HTTP traffic Matched by {type_check} / Source: {src_ip} / Destination: {dst_ip} / Host: {host} / Payload: [ {payload[:100]}  ] ...")
        print("--------------------")

def load_yaml(file_path: str) -> Dict:
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def capture_packets(rule: Dict, interface: str = "eth0"):
    analyzer = HTTPAnalyzer(rule)
    print(f"Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=analyzer.analyze_packet, store=0)

if __name__ == "__main__":
    # get argomans from cli
    if len(sys.argv) < 2:
        print("No rule data provided.")
    rule_yaml = sys.argv[1]
    
    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        print("Failed to decode YAML.")

    configs = load_yaml('config.yaml')
    print("Created By wikm with ❤️ ")
    print("Version 1.1")
    print("Starting ... ")
    interface = configs['io']['interface']
    capture_packets(rule, interface)