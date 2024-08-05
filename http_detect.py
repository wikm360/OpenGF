import yaml
from scapy.all import sniff, IP, TCP, Raw
import re
import sys
from telegram import send_to_telegram
import subprocess
import signal

def add_iptables_rule(ip, port):
    if not port :
        port = 80
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

class HTTPAnalyzer:
    def __init__(self, rule):
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
                if rule['action'] == 'check' or rule['action'] == 'block' :
                    if rule['ip'] == "all" : #Just http detect
                        self.log_traffic(src_ip, dst_ip, payload , host , "nothing")
                        if rule['action'] == 'block' :
                            add_iptables_rule(dst_ip, dst_port)
                    if self.rule['type'] == 'http' and (src_ip == self.rule['ip'] or dst_ip == self.rule['ip']) and self.check_host(payload):
                        self.log_traffic(src_ip, dst_ip, payload , host , "ip and host")
                        if rule['action'] == 'block' :
                            add_iptables_rule(dst_ip, dst_port)
                    elif self.rule['type'] == 'http' and (src_ip == self.rule['ip'] or dst_ip == self.rule['ip']):
                        self.log_traffic(src_ip, dst_ip, payload , host , "ip")
                        if rule['action'] == 'block' :
                            add_iptables_rule(dst_ip, dst_port)
                    elif self.rule['type'] == 'http' and self.check_host(payload):
                        self.log_traffic(src_ip, dst_ip, payload , host , "host")
                        if rule['action'] == 'block' :
                            add_iptables_rule(dst_ip, dst_port)

    def is_http(self, payload):
        return bool(self.http_pattern.match(payload))

    def check_host(self, payload):
        # check rule host with host header
        host_pattern = re.compile(rb'Host: (.+?)\r\n')
        match = host_pattern.search(payload)
        if match:
            host = match.group(1).decode()
            return host == self.rule['host']
        return False

    def log_traffic(self, src_ip, dst_ip, payload , host , type_check):
        mess = f"HTTP traffic Matched by {type_check} / Source: {src_ip} / Destination: {dst_ip} / Host: {host} / Payload: [ {payload[:100]}  ] ..."
        print(mess)
        print("--------------------")
        send_to_telegram(mess)


def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def capture_packets(rule, interface = "eth0"):
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
    interface = configs['io']['interface']

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

    capture_packets(rule, interface)