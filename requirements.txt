# packet_sniffer.py

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import time

class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.packet_buffer = []

    def process_packet(self, packet):
        if IP in packet:
            ip = packet[IP]

            protocol = ip.proto
            packet_length = len(packet)

            src_port = 0
            dst_port = 0

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            packet_info = {
                "timestamp": time.time(),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": protocol,
                "packet_length": packet_length,
                "src_port": src_port,
                "dst_port": dst_port
            }

            self.packet_buffer.append(packet_info)

            self.callback(packet_info)

    def start(self):
        sniff(prn=self.process_packet, store=False)