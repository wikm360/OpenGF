
# OpenGF

OpenGF is a flexible, easy-to-use, open source implementation of GF (Great Firewall) on Linux . based python

features:

1)detect and block http traffic (based on http header or ip)

2)detect and block tla traffic (based on sni or ip)

3)detect and block ssh traffic (based on ip ans port)

4)detect and block traffic based Geoip

5)detect and block traffic based on geosite

6)Easy to write rules 

7)send reports on telegram

8)Reading rules in both hierarchical and parallel ways 



## Prerequisites

Before installing the required libraries, you must first install Python and pip . python libraries :

```bash
  pip install scapy
  pip install subprocess
  pip install yaml
  pip install signal
  pip install sys
  pip install ipaddress
  pip install os
  pip install json

```
Iptable :

```bash
  sudo apt update
  sudo apt install iptables
```


## Deployment

To deploy this project run

```bash
  cd /~
  wget https://github.com/wikm360/OpenGF/releases/latest/download/OpenGF.zip
  sudo unzip OpenGF.zip -d ~/OpenGF
  cd OpenGF/
  sudo python3 main.py
```


## Usage/Examples
First change config.yaml variable with your own .

```bash
  cd /~
  cd OpenGF/
  nano config.yaml
```

Eample of config.yaml :

```yaml
io:
  interface: "enp4s0" #interface or all

telegram:
  token: "None" #your bot token : get from https://t.me/BotFather , if you dont use it = None
  chatid: "#########" # your chat id : get from https://t.me/chatIDrobot
core:
  rule_type: "parallel" # hierarchy or parallel
path:
  geoip: "./geo/GeoIP.txt"
  geosite: "./geo/GeoSite.txt"

```



🔴NOTIC : check type = just detect and report it to cli and telegram.


🔴NOTIC : block type = detect , block and report it to cli and telegram.



Rules Examples : change rules.yaml file :
```bash
  cd /~
  cd OpenGF/
  nano rules.yaml
```
Rules Example 

HTTP :

```yaml

  - name: just http detect
    action: "check" #ckeck or block
    type: http
    ip: "all" # ip or all
    host: "None" #host header or None

  - name: matched by ip
    action: "check"
    type: http
    ip: "185.128.136.186" # ip or all
    host: "None"

  - name: match by host
    action: "check"
    type: http
    ip: "None"
    host: "wikm.ir"

  - name: match by both ip and host
    action: "block"
    type: http
    ip: "185.128.136.186"
    host: "wikm.ir"
```
TLS

```yaml

  - name: match by ip port 443
    action: "check" #check or block
    type: tls
    ip: "185.15.59.224" #ip or None
    sni: "None" #sni or None
    port: "443" #port or all

  - name: match by ip and all ports
    action: check
    type: tls
    ip: "185.15.59.224"
    sni: "None"
    port: all

  - name: match by sni and all ports
    action: "block"
    type: tls
    ip: "None"
    sni: "wikm.ir"
    port: all

  - name: match by sni and ip
    action: "block"
    type: tls
    ip: "185.15.59.224"
    sni: "fa.wikipedia.org"
    port: all

  - name: match by sni
    action: check
    type: tls
    ip: "185.128.136.186"
    sni: "netplusshop.ir"
    port: all

```
Geosite

```yaml

  - name: Geosite match
    action: block
    type: geosite

```
GeoIP

```yaml

  - name: Geoip match
    action: "block" #block or check
    transport: all #tcp or udp
    type: geoip

```


SSH

```yaml
  - name: ssh block
    type: ssh
    action: "block"
    ip: "all" #port or all

```



Example of GeoIP.txt :

```bash

1.1.1.1/32
185.128.136.0/24

```


Example of GeoSite.txt :

```bash

wikm.ir
soft98.ir
didi.ir
downloadha.com

```
