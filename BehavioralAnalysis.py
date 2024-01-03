from scapy.all import *

class BehavioralAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packet_count_threshold = 5000
        self.ip_communication_threshold = 500
        self.ip_communication_count = {}

    def analyze_packet_count(self):
        packet_count = sum(1 for _ in rdpcap(self.pcap_file))

        if packet_count > self.packet_count_threshold:
            print(f"Unusual behavior: High packet count detected ({packet_count} packets).")

    def analyze_ip_communication(self):
        packets = rdpcap(self.pcap_file)

        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                key = (src_ip, dst_ip)
                self.ip_communication_count[key] = self.ip_communication_count.get(key, 0) + 1

        for key, count in self.ip_communication_count.items():
            if count > self.ip_communication_threshold:
                print(f"Unusual behavior: High communication count between {key[0]} and {key[1]} ({count} packets).")
