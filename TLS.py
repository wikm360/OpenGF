from scapy.all import *
from scapy.all  import IP , TCP
from scapy.layers.tls.all import TLS
from scapy.layers.tls.extensions import TLS_Ext_ServerName
import yaml
from typing import Dict
from telegram import send_to_telegram

def log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port , type_check):
    mess = f"TLS traffic Matched by {type_check} / SNI: {sni} /  {src_ip}:{src_port} > {dst_ip}:{dst_port}  / packet: {packet.summary()}  ] ..."
    print(mess)
    print("--------------------")
    send_to_telegram(mess)

def load_yaml(file_path: str) -> Dict:
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

#tls_client_hello_pattern = re.compile(rb'\x16\x03[\x00-\x03][\x00-\xff]{2}\x01\x00')
def packet_callback(packet):
    if packet.haslayer(TLS):
        sni = ""
        if packet.haslayer(TLS_Ext_ServerName):
            #print(packet[TLS_Ext_ServerName].show())
            sni = packet[TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')
        
        dst_ip = packet[IP].dst
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_port  = packet[TCP].dport

        if rule['ip'] == "all" : #Just TLS detect
            log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port , "all")
        if rule['ip']==dst_ip and rule['sni'] == sni :
            log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port ,"ip and sni")
        elif rule['ip'] == dst_ip :
            log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port ,"ip")
        elif rule['sni'] == sni :
            log_traffic(packet,sni, src_ip , dst_ip , src_port , dst_port ,"sni")
        
            #print("Packet details:")
            #packet.show()

# Set up the packet capture
if len(sys.argv) < 2:
    print("No rule data provided.")
rule_yaml = sys.argv[1]

try:
    rule = yaml.safe_load(rule_yaml)
except yaml.YAMLError:
    print("Failed to decode YAML.")

configs = load_yaml('config.yaml')
interface = configs['io']['interface']
filter_exp = f"tcp port {rule['port']}"  # Filter 

print(f"Filter : {filter_exp}")

print(f"Starting packet capture on interface {interface}")

if rule['port'] == "all" :
    sniff(iface=interface, prn=packet_callback , session=TCPSession)
elif rule['port'] == "https" :
    sniff(iface=interface, filter="tcp port 443", prn=packet_callback , session=TCPSession)
else :
    sniff(iface=interface, filter=filter_exp, prn=packet_callback , session=TCPSession)

