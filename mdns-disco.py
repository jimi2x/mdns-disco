#!/usr/bin/env python3
from scapy.all import *
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from mac_vendor_lookup import MacLookup
import time
import os

SAMPLE_DATA = []
TOTAL_CONNS = 0

###################################################################################
#  mdns-disco.py ---> Instructions & How To (run as root):                        #
#                                                                                 #
#   [+] Scanning a /24 network (Note: Needs x.x.x.0/24 format to work properly!)  #
#       sudo python3 mdns-disco.py 192.168.1.0/24                                 #
#                                                                                 #
#   [+] Auto exports CSV file named "MDNS-DISCO-RESULTS.csv" in local directory!  #
#       Hit CTRL-C to quit when you are done!                                     #
###################################################################################

def vendor_lookup(srcmac):
    try:
        new_vendor = MacLookup().lookup(srcmac)
    except:
        pass
        new_vendor = "--"
    return new_vendor

def draw_table(SAMPLE_DATA):
    console = Console()
    table = Table(
        title="[bold white] 🐇🐇🐇 mDNS Network Host Discovery Results 🐇🐇🐇 [/bold white]",
        box=box.DOUBLE_EDGE,
        border_style="bright_blue",
        header_style="bold white on dark_blue",
        show_lines=True,
        padding=(0, 1),
        title_style="bold",
    )
    table.add_column("Hostname",       style="bold green",        min_width=15)
    table.add_column("MDNS Name",      style="light_green",       min_width=20)
    table.add_column("MAC Address",    style="bright_yellow",     min_width=15)
    table.add_column("Vendor",         style="yellow",            min_width=15)
    table.add_column("IPv4 Address",   style="bright_blue",       min_width=10)
    table.add_column("IPv6 Address",   style="bright_cyan",       min_width=10)
    table.add_column("Data",           style="bright_red",        min_width=10, overflow="fold")
    for row in SAMPLE_DATA:
        table.add_row(
            row["hostname"],
            row["mdns_name"],
            row["mac"],
            row["new_vendor"],
            row["ipv4"],
            row["ipv6"],
            row["data"],
        )
    os.system('clear')
    console.print()
    console.print(table)
    console.print()
    console.print(f"Total Hosts: [green]{len(SAMPLE_DATA)}[/green]\n")


def add_entry(hostname,mdns_name,srcmac,new_vendor,ipv4,ipv6,data):
    new_entry =   {
        "hostname":    hostname,
        "mdns_name":   mdns_name,
        "mac":         srcmac,
        "new_vendor":  new_vendor,
        "ipv4":        ipv4,
        "ipv6":        ipv6,
        "data":        data,
    }
    existing_hostnames = [entry["hostname"] for entry in SAMPLE_DATA]
    new_hostname = new_entry["hostname"]
    new_entry["data"] = new_entry["data"].replace(', ', ',')
    if new_entry["hostname"] not in existing_hostnames:
        SAMPLE_DATA.append(new_entry)
    else:
        for i, d in enumerate(SAMPLE_DATA):
            h = d['hostname']
            if h == new_hostname:
                index_id = i
                index_id_str = str(index_id)
                if d['data']:
                    existing = d['data'].split(',')
                    d['data'] = ','.join(existing + [new_entry["data"]])
                else:
                    d['data'] = new_entry["data"]
                d['data'] = d['data'].replace(', ', ',')
                existing = d['data'].split(',')
                existing_new = list(set(existing))
                d['data'] = ','.join(existing_new)
    draw_table(SAMPLE_DATA)


print("\n")
print(r"        ___  _  _ ___      ___  _             ")            
print(r"  _ __ |   \| \| / __| 🪩 |   \(_)___ __ ___  ") 
print(r" | '  \| |) | .` \__ \ 🕺 | |) | (_-</ _/ _ \ ")
print(r" |_|_|_|___/|_|\_|___/ 🕳️  |___/|_/__/\__\___/ ")
print("   Presented by Lost Rabbit Labs :: ver 0.1a \n")

print("🪩🪩🪩 Attempting to discover mDNS hosts, please be patient...\n")

b = 0

try:
    input_addr = sys.argv[1]
    network_addr = input_addr.split("0/")[0]
    reversed_ip = ".".join(network_addr.split(".")[::-1])
    addrarpa = reversed_ip + ".in-addr.arpa"
except:
    print ("⁉️  User Error Detected ⁉️\n\nExample usage:  python3 mdns-disco.py 192.168.1.0/24\n")
    sys.exit()

while b < 256:
    b1 = str(b)
    ipaddr = b1 + addrarpa
    ip = network_addr + b1
    newfilter = "port 53 or port 5353 and src host " + ip 
    a = AsyncSniffer(filter=newfilter)
    t = 0
    print(f"\rProgress: " + b1 + " of 255", end="", flush=True)
    while t < 1:
        a.start()
        send(IP()/UDP(dport=5353)/DNS(rd=1,qd=DNSQR(qname=ipaddr, qtype='PTR')),verbose=False)
        time.sleep(.5)
        results = a.stop()
        try:
            results0 = str(results[0])
            mdns_name = results0.split("b'")[1].strip(".'")
            srcmac = results[0][Ether].src
            new_vendor = vendor_lookup(srcmac)
            b = b + 1
            services = ""
            hostname = ip
            ipv4 = ip
            ipv6 = ""
            data = ""
            add_entry(hostname,mdns_name,srcmac,new_vendor,ipv4,ipv6,data)
        except:
            pass
            b = b + 1
        t = t + 1
        b_str = str(b)
        print(f"\rProgress: " + b_str + " of 255", end="", flush=True)
print(f"\r                             ")

ipv4 = ""
ipv6 = ""
ipv4src = ""
ipv6src = ""
data = ""
srcmac = ""

def packet_callback(packet):
    all_mdns = []
    # Uncomment below to print packets OTF!
    #packet.show()
    dnsrr = packet[DNS]
    srcmac = packet[Ether].src
    dstmac = packet[Ether].dst
    new_vendor = vendor_lookup(srcmac)
    try:
        srcaddr = packet[IP].src
        dstaddr = packet[IP].dst    
        ipv4src = srcaddr
        ipv4dst = dstaddr
        ipv6src = ""
        ipv6dst = ""
    except:
        srcaddr = packet[IPv6].src
        dstaddr = packet[IPv6].dst
        ipv6src = srcaddr
        ipv6dst = dstaddr
        ipv4src = ""
        ipv4dst = ""
        pass
        # add timestamp to output before release
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        for x in dnsrr.qd:
            dnsrrqd_val = x.qname.decode("utf-8")
            all_mdns.append(dnsrrqd_val)
    except:
        pass
    try:
        for x in dnsrr.an:
            dnsrran_val = x.rdata.decode("utf-8")
            all_mdns.append(dnsrran_val)
    except:
        pass
        try:
            r1 = packet.an[3].rdata
            try:
               pd3 = [b.decode('utf-8') for b in r1]
               packetrdata3 = str(pd3)
            except:
                pass
                r1a = str(r1)
                all_mdns.append(r1a)
            all_mdns.append(packetrdata3)
        except:
            pass
        try:
            r2 = packet.an[4].rdata
            r2_val = packet.an[4].rdata.decode("utf-8")
            all_mdns.append(r2)
            all_mdns.append(r2_val)
        except:
            pass
    try:
        for x1 in dnsrr.an:
            x_val = x1.rrname.decode("utf-8")
            all_mdns.append(x_val)
    except:
        pass
    output = srcaddr + ";" + srcmac + ";" + dstaddr  + ";" + dstmac + ";"
    all_mdns_final = set(all_mdns)
    new_list_final = ", ".join(map(str, all_mdns_final))
    data = new_list_final
    if ipv4src != "":
        hostname = ipv4src
    else:
        hostname = ipv6src
    mdns_name = ""
    add_entry(hostname,mdns_name,srcmac,new_vendor,ipv4src,ipv6src,data)
    with open ("MDNS-DISCO-RESULTS.csv", "a") as outputfile:
        outputfile.write(output)
        outputfile.write(new_list_final)
        outputfile.write("\n")
    hostname = ""
    ipv4 = ""
    ipv6 = ""
    ipv4src = ""
    ipv6src = ""
    data = ""
    srcmac = ""

sniff(prn=packet_callback, filter="udp and port 5353", store=0)
