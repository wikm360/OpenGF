import yaml
from scapy.all import sniff
from telegram import send_to_telegram
import signal
from http_detect import HTTPAnalyzer
from TLS import analyzer_tls
import os
from signal_module import signal_handler , cleanup_iptables
from GeoIP import handle_packet
import ipaddress
from GeoSite import analyze_goesite
from ssh import analyze_ssh

def packet_callback (packet) :
    for rule in rules['rules']:
        type = rule['type']
        if type == 'http':
            analyzer = HTTPAnalyzer(rule)
            analyzer.analyze_packet(packet=packet , rule=rule , configs=configs)
        elif type == 'tls':
            analyzer_tls(packet=packet , rule=rule , configs=configs)
        elif type == 'geosite' :
            analyze_goesite(packet=packet , rule=rule , configs=configs , domains=domains)
        elif type == 'geoip' :
            transport = rule['transport']
            handle_packet(packet=packet , rule=rule , configs=configs , ips=ips , transport=transport)
        elif type == 'ssh'  :
            analyze_ssh(packet=packet , rule=rule , configs=configs)
        else:
            print(f"Unknown rule type: {rule['type']}")
        

def load_yaml(file_path):

    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

if __name__  == "__main__" :
    configs = load_yaml('config.yaml')
    interface = configs['io']['interface']
    rules = load_yaml('rules.yaml')

    #geoip settings
    def list_ips(ip_range):
        network = ipaddress.ip_network(ip_range)
        return [str(ip) for ip in network.hosts()]
    path_geoip  = configs['path']['geoip']
    path_geosite  = configs['path']['geosite']
    ip_ranges = []
    ips = set()
    with open (path_geoip  , "r") as f:
        for line in f :
            range = line.strip()
            ip_ranges.append(range)

    for ip_range in ip_ranges:
        temp = []
        temp = list_ips(ip_range)
        ips.update(temp)
    iptable_rules = []

    #Geosite settings
    domains = {}
    with open (path_geosite  , "r") as f:
        for line in f :
            domain = line.strip()
            domains[domain] = []

    print(f"Starting packet capture on interface {interface}...")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if interface == "all" :
        sniff(prn=packet_callback, store=0)
    else :
        sniff(iface=interface , prn=packet_callback, store=0)
