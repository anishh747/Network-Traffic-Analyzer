import dpkt
import csv
from datetime import datetime

def analyze_tcp_connections(pcap_file, output_csv):
    tcp_connections = {}

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_ip = dpkt.utils.inet_to_str(ip.src)
                    dst_ip = dpkt.utils.inet_to_str(ip.dst)
                    src_port = tcp.sport
                    dst_port = tcp.dport

                    connection_key = (src_ip, src_port, dst_ip, dst_port)

                    if connection_key not in tcp_connections:
                        tcp_connections[connection_key] = {
                            'start_time': timestamp,
                            'end_time': timestamp,
                            'packet_count': 1,
                        }
                    else:
                        tcp_connections[connection_key]['end_time'] = timestamp
                        tcp_connections[connection_key]['packet_count'] += 1

        for connection_key, connection_info in tcp_connections.items():
            print(f"TCP Connection: {connection_key}")
            print(f"Start Time: {datetime.fromtimestamp(connection_info['start_time']).strftime('%H:%M:%S.%f')}")
            print(f"End Time: {datetime.fromtimestamp(connection_info['end_time']).strftime('%H:%M:%S.%f')}")
            print(f"Packet Count: {connection_info['packet_count']}")
            print("-" * 40)

    # Export to CSV
    with open(output_csv, 'w', newline='') as csv_file:
        fieldnames = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port',
                      'Start Time', 'End Time', 'Packet Count']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        for connection_key, connection_info in tcp_connections.items():
            writer.writerow({
                'Source IP': connection_key[0],
                'Source Port': connection_key[1],
                'Destination IP': connection_key[2],
                'Destination Port': connection_key[3],
                'Start Time': connection_info['start_time'],
                'End Time': connection_info['end_time'],
                'Packet Count': connection_info['packet_count']
            })

