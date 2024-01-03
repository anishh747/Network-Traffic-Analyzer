from dpkt_analysis import analyze_tcp_connections
from BehavioralAnalysis import BehavioralAnalyzer
from malicious_count import query_virustotal

if __name__ == "__main__":
    pcap_file = 'test_packets.pcap'

    try:     
        # TCP Connections check
        analyze_tcp_connections(pcap_file,'output.csv')

        # Behavioral Analysis (High Communication, Low Communication)
        # analyzer = BehavioralAnalyzer(pcap_file)
        # analyzer.analyze_packet_count()
        # analyzer.analyze_ip_communication()

        # Malicious IP check
        # query_virustotal(pcap_file)

    except Exception as e:
        print(f"An error occurred: {e}")
