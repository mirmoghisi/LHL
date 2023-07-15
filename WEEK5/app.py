from scapy.all import *
from ipaddress import ip_network, IPv4Address

def analyze_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        icmp_ip_count = {}
        tcp_syn_ip_count = {}
        tcp_ack_ip_count = {}
        udp_ip_count = {}
        arp_ping_ip_count = {}

        local_network = "172.16.14.0/24"
        local_network_ip = ip_network(local_network)

        for packet in packets:
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    if IPv4Address(src_ip) in local_network_ip:
                        if src_ip in icmp_ip_count:
                            icmp_ip_count[src_ip] += 1
                        else:
                            icmp_ip_count[src_ip] = 1
            elif packet.haslayer(TCP) and packet[TCP].flags == "S":
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    if IPv4Address(src_ip) in local_network_ip:
                        if src_ip in tcp_syn_ip_count:
                            tcp_syn_ip_count[src_ip] += 1
                        else:
                            tcp_syn_ip_count[src_ip] = 1
            elif packet.haslayer(TCP) and packet[TCP].flags == "A":
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    if IPv4Address(src_ip) in local_network_ip:
                        if src_ip in tcp_ack_ip_count:
                            tcp_ack_ip_count[src_ip] += 1
                        else:
                            tcp_ack_ip_count[src_ip] = 1
            elif packet.haslayer(UDP):
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    if IPv4Address(src_ip) in local_network_ip:
                        if src_ip in udp_ip_count:
                            udp_ip_count[src_ip] += 1
                        else:
                            udp_ip_count[src_ip] = 1
            elif packet.haslayer(ARP) and packet[ARP].op == 1:
                src_ip = packet[ARP].psrc
                if IPv4Address(src_ip) in local_network_ip:
                    if src_ip in arp_ping_ip_count:
                        arp_ping_ip_count[src_ip] += 1
                    else:
                        arp_ping_ip_count[src_ip] = 1

        print(f"Analyzing file: {pcap_file}\n")
        if icmp_ip_count:
            max_count = max(icmp_ip_count.values())
            max_ips = [ip for ip, count in icmp_ip_count.items() if count == max_count]
            print("ICMP Echo Request:")
            print(f"IP address(es) with the most packets: {', '.join(max_ips)} (Packets: {max_count})")
        else:
            print("ICMP Echo Request: No packets found.")

        if tcp_syn_ip_count:
            max_count = max(tcp_syn_ip_count.values())
            max_ips = [ip for ip, count in tcp_syn_ip_count.items() if count == max_count]
            print("\nTCP SYN Scan:")
            print(f"IP address(es) with the most packets: {', '.join(max_ips)} (Packets: {max_count})")
        else:
            print("TCP SYN Scan: No packets found.")

        if tcp_ack_ip_count:
            max_count = max(tcp_ack_ip_count.values())
            max_ips = [ip for ip, count in tcp_ack_ip_count.items() if count == max_count]
            print("\nTCP ACK Scan:")
            print(f"IP address(es) with the most packets: {', '.join(max_ips)} (Packets: {max_count})")
        else:
            print("TCP ACK Scan: No packets found.")

        if udp_ip_count:
            max_count = max(udp_ip_count.values())
            max_ips = [ip for ip, count in udp_ip_count.items() if count == max_count]
            print("\nUDP Scan:")
            print(f"IP address(es) with the most packets: {', '.join(max_ips)} (Packets: {max_count})")
        else:
            print("UDP Scan: No packets found.")

        if arp_ping_ip_count:
            max_count = max(arp_ping_ip_count.values())
            max_ips = [ip for ip, count in arp_ping_ip_count.items() if count == max_count]
            print("\nARP Ping Scan:")
            print(f"IP address(es) with the most packets: {', '.join(max_ips)} (Packets: {max_count})")
        else:
            print("ARP Ping Scan: No packets found.")

        print()
    except Exception as e:
        print(f"Error analyzing pcap file {pcap_file}: {str(e)}")

# Provide the folder path where your pcapng files are located
folder_path = "PCAPNG files/"

# Iterate over the pcapng files in the folder
import os
for filename in os.listdir(folder_path):
    if filename.endswith(".pcapng"):
        pcap_file = os.path.join(folder_path, filename)
        analyze_pcap(pcap_file)
