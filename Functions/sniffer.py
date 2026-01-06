#!/usr/bin/env python3

"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Packet capture and analysis using Scapy.
Captures network traffic, analyzes protocols, ports, and DNS queries,
and exports results to CSV files. Supports filtering by protocol and MITM traffic.
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, sniff, wrpcap
import csv
import sys
from collections import Counter

def analyze_pcap(pcap_file):
    """Analyze captured packets and generate statistics"""
    # Read packets from PCAP file
    packets = rdpcap(pcap_file)

    # Initialize counters for analysis
    protocol_count = Counter()
    ip_count = Counter()
    port_count = Counter()
    dns_queries = []

    # Process each packet
    for pkt in packets:
        # Count protocols
        if pkt.haslayer(TCP):
            protocol_count['TCP'] += 1
            port_count[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            protocol_count['UDP'] += 1
            port_count[pkt[UDP].dport] += 1
        elif pkt.haslayer(ICMP):
            protocol_count['ICMP'] += 1
        elif pkt.haslayer(ARP):
            protocol_count['ARP'] += 1

        # Count IPs (both source and destination)
        if pkt.haslayer(IP):
            ip_count[pkt[IP].src] += 1
            ip_count[pkt[IP].dst] += 1

        # Extract DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            dns_queries.append(query)


    # Save to CSV files
    save_protocols_csv(protocol_count, 'protocols.csv')
    save_ips_csv(ip_count, 'top_ips.csv')
    save_ports_csv(port_count, 'top_ports.csv')

    # Save DNS queries if any were found
    if dns_queries:
        save_dns_csv(dns_queries, 'dns_queries.csv')


def get_service(port):
    """Map port numbers to common service names"""
    services = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP',
        5353: 'mDNS', 8080: 'HTTP-ALT', 1900: 'SSDP'
    }
    return services.get(port, 'Unknown')

def save_protocols_csv(protocol_count, filename):
    """Save protocol statistics to CSV"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Protocol', 'Count'])
        # Write protocols sorted by count (most common first)
        for proto, count in protocol_count.most_common():
            writer.writerow([proto, count])

def save_ips_csv(ip_count, filename):
    """Save top IP addresses to CSV"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP Address', 'Packet Count'])
        # Write top 20 most active IPs
        for ip, count in ip_count.most_common(20):  # Top 20
            writer.writerow([ip, count])

def save_ports_csv(port_count, filename):
    """Save top ports and their services to CSV"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Service', 'Count'])
        # Write top 20 most active ports
        for port, count in port_count.most_common(20):  # Top 20
            service = get_service(port)
            writer.writerow([port, service, count])

def save_dns_csv(dns_queries, filename):
    """Save DNS query statistics to CSV"""
    # Count unique queries
    query_count = Counter(dns_queries)

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Domain', 'Query Count'])
        # Write queries sorted by frequency
        for query, count in query_count.most_common():
            writer.writerow([query, count])

def sniffer(pcapname, time=10):
    """Capture network packets for specified duration"""
    # Capture packets for given time period
    capture = sniff(timeout=time)
    # Save captured packets to PCAP file
    wrpcap(pcapname, capture)

def filter_packets(pcap_file, protocol):
    """Filter packets by protocol and save to new PCAP file"""

    # Read all packets from file
    packets = rdpcap(pcap_file)
    filtered = []

    # Filter packets based on protocol
    for pkt in packets:
        if protocol.lower() == 'tcp' and pkt.haslayer(TCP):
            filtered.append(pkt)
        elif protocol.lower() == 'udp' and pkt.haslayer(UDP):
            filtered.append(pkt)
        elif protocol.lower() == 'icmp' and pkt.haslayer(ICMP):
            filtered.append(pkt)
        elif protocol.lower() == 'arp' and pkt.haslayer(ARP):
            filtered.append(pkt)
        elif protocol.lower() == 'dns' and pkt.haslayer(DNS):
            filtered.append(pkt)
        elif protocol.lower() == 'http':
            # Filter HTTP traffic (port 80)
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                filtered.append(pkt)
        elif protocol.lower() == 'https':
            # Filter HTTPS traffic (port 443)
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                filtered.append(pkt)


    # Save filtered packets to new file
    if filtered:
        output = f"{protocol}_filtered.pcap"
        wrpcap(output, filtered)

    return filtered

def filter_mitm_traffic(pcap_file, target_ip):
    """Filter PCAP to only show traffic from/to a specific target IP (for MITM captures)"""
    print(f"Filtering MITM traffic for target: {target_ip}")
    # Read all packets from capture
    packets = rdpcap(pcap_file)
    print(f"Total packets before filtering: {len(packets)}")
    
    # Filter to only packets involving the target device
    filtered_packets = [pkt for pkt in packets if pkt.haslayer(IP) and 
                       (pkt[IP].src == target_ip or pkt[IP].dst == target_ip)]
    
    print(f"Packets after MITM filtering: {len(filtered_packets)}")
    
    # Collect unique IPs that communicated with target
    unique_ips = set()
    for pkt in filtered_packets:
        if pkt.haslayer(IP):
            unique_ips.add(pkt[IP].src)
            unique_ips.add(pkt[IP].dst)
    
    print(f"Target device ({target_ip}) communicated with IPs: {sorted(unique_ips)}")
    
    # Overwrite the original file with filtered packets
    wrpcap(pcap_file, filtered_packets)
    print(f"✓ Saved {len(filtered_packets)} filtered packets back to {pcap_file}")
    
    return len(filtered_packets)

if __name__ == "__main__":
    # Main execution - capture or analyze based on arguments
    if len(sys.argv) == 1:
        # No arguments - start new capture
        print("starting new capture")
        sniffer("output.pcap")
    else:
        # Arguments provided - analyze existing capture
        print("loading pcap from memory")
        analyze_pcap("output.pcap")
        filter_packets("output.pcap", "http")
