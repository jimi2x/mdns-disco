<h1> mdns-disco.py </h1>
<p><strong>mDNS Disco</strong> is a free Linux/Unix security discovery & threat hunting tool (Python3 script) that performs mDNS host and services discovery on your local /24 network and sniffs all IPv4 & IPv6 <strong>UDP:5353</strong> traffic.</p>

## Original script
<strong>jimi2x</strong>

---
## Functions
* **IPv4 Enumeration of mDNS hosts in local network**
* **OUI Lookups for MACs**
* **Discovered services logging**
* **Rogue device/mDNS sniffer detection**
* **IPv6 device detection**
* **CSV export of all captured data**

---
## Quick install notes:
```
pip3 install rich
pip3 install mac_vendor_lookup
pip3 install scapy
```

---
## Example Usage:
```
chmod 755 mdns-disco.py
./mdns-disco.py 192.168.1.0/24

Mash CTRL-C to quit.
```
---
## License
MIT License
