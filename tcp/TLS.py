from scapy.all import *
from scapy.all  import IP , TCP
from scapy.layers.tls.all import TLS
from scapy.layers.tls.extensions import TLS_Ext_ServerName
import yaml
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from settings.telegram import send_to_telegram
import subprocess
import signal
import json
import time

def add_iptables_rule(ip, port ,configs):
    if not port :
        port = 443
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

def log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port , type_check):
    mess = f"TLS traffic Matched by {type_check} / SNI: {sni} /  {src_ip}:{src_port} > {dst_ip}:{dst_port}  / packet: {packet.summary()}  ] ..."
    print(mess)
    print("--------------------")
    send_to_telegram(mess)

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def packet_callback (packet) :
    analyzer_tls(packet=packet  , rule=rule , configs=configs)

#tls_client_hello_pattern = re.compile(rb'\x16\x03[\x00-\x03][\x00-\xff]{2}\x01\x00')
def analyzer_tls(packet , rule , configs):
    if packet.haslayer(TLS):
        sni = ""
        if packet.haslayer(TLS_Ext_ServerName):
            #print(packet[TLS_Ext_ServerName].show())
            sni = packet[TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')
        
        dst_ip = packet[IP].dst
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_port  = packet[TCP].dport
        if rule['action'] == 'check' or rule['action'] == 'block' :
            if rule['ip'] == "all" : #Just TLS detect
                log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port , "nothing")
                if rule['action'] == 'block' :
                    add_iptables_rule(dst_ip, dst_port , configs)
            if rule['ip']==dst_ip and rule['sni'] == sni :
                log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port ,"ip and sni")
                if rule['action'] == 'block' :
                    add_iptables_rule(dst_ip, dst_port, configs)
            elif rule['ip'] == dst_ip :
                log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port ,"ip")
                if rule['action'] == 'block' :
                    add_iptables_rule(dst_ip, dst_port, configs)
            elif rule['sni'] == sni :
                log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port ,"sni")
                if rule['action'] == 'block' :
                    add_iptables_rule(dst_ip, dst_port, configs)
        
            #print("Packet details:")
            #packet.show()

if __name__ == "__main__"  :
    # Set up the packet capture
    if len(sys.argv) < 2:
        print("No rule data provided.")
    rule_yaml = sys.argv[1]

    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        print("Failed to decode YAML.")

    configs = load_yaml('./settings/config.yaml')
    interface = configs['io']['interface']
    filter_exp = f"tcp port {rule['port']}"  # Filter 

    print(f"Filter : {filter_exp}")

    print(f"Starting packet capture on interface {interface}")

    iptable_rules = []

    def signal_handler(sig, frame):
        cleanup_iptables(iptable_rules)
        sys.stdout.write("Cleaning up iptables rules...")
        time.sleep(2)
        sys.exit(0)
        time.sleep(2)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if rule['port'] == "all" :
        sniff(iface=interface, prn=packet_callback , session=TCPSession)
    elif rule['port'] == "https" :
        sniff(iface=interface, filter="tcp port 443", prn=packet_callback , session=TCPSession)
    else :
        sniff(iface=interface, filter=filter_exp, prn=packet_callback , session=TCPSession)

