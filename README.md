
# OpenGF

OpenGF is a flexible, easy-to-use, open source implementation of GF (Great Firewall) on Linux . based python


## Prerequisites

Before installing the required libraries, you must first install Python and pip . python libraries :

```bash
  pip install scapy
  pip install subprocess
  pip install yaml
  pip install signal
  pip install sys
  pip install ipaddress

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

NOTIC : check type = just detect and report it to cli and telegram.


NOTIC : block type = detect and block and report it to cli and telegram.



Rules Examples : change rules.yaml file :
```bash
  cd /~
  cd OpenGF/
  nano rules.yaml
```
Rules Example 

http :

```yaml
  - name: just http detect
    action: "check" # check or block
    type: http
    ip: "all" # ip or all
    host: "None" #host header or None

  - name: matched by ip and block
    action: block
    type: http
    ip: "185.128.136.186"
    host: "None"

  - name: match by host
    action: check
    type: http
    ip: "None"
    host: "wikm.ir"

  - name: match by both ip and host
    action: block
    type: http
    ip: "185.128.136.186"
    host: "wikm.ir"
```
TLS :
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
    action: check
    type: tls
    ip: "None"
    sni: "wikm.ir"
    port: all

  - name: match by sni and ip and block
    action: block
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
    action: "block" #check or block
    type: geosite
    path: "./GeoSite.txt" #path of your geosite file

```
GeoIP

```yaml
  - name: Geoip match
    action: "block" #block or check
    transport: "all" #tcp or udp or all
    type: geoip
    path: "./GeoIP.txt" #path of your geoip file
```
