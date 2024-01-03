import requests
from scapy.all import *

def extract_unique_ips(pcap_file):
    unique_ips = set()
    packets = rdpcap(pcap_file)

    for packet in packets:
        if IP in packet:
            unique_ips.add(packet[IP].src)
            unique_ips.add(packet[IP].dst)

    return unique_ips

def extract_threat_info(threat_data):
    if threat_data:
        ip_address = threat_data.get('data', {}).get('id')
        last_analysis_stats = threat_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_count = last_analysis_stats.get('malicious', 0)

        print(f"IP Address: {ip_address}")
        print(f"Malicious Count: {malicious_count}")
    else:
        print("No threat intelligence data found.")

def query_virustotal(pcap_file):
    indicators = extract_unique_ips(pcap_file)
    api_key = '4ca4e1facf28fe133a7686a0ad56943a58bc81de22417a0ab8d09780eacc69f2'

    for indicator in indicators:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}' 
        headers = {'x-apikey': api_key}

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            threat_data = response.json()
            if threat_data:
                extract_threat_info(threat_data)
            else:
                print(f"No threat intelligence data found for {indicator}.")
            print("-" * 40)
        
