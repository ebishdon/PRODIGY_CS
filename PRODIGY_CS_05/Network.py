import scapy.all as scapy
import time
import logging
import sys
from tabulate import tabulate

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

analyzed_packets = []  # List to store analyzed packets

def analyze_tcp(packet):
    """Analyze TCP packets."""
    tcp_src_port = packet[scapy.TCP].sport
    tcp_dst_port = packet[scapy.TCP].dport
    tcp_payload = packet[scapy.TCP].payload
    if isinstance(tcp_payload, bytes):
        tcp_payload = tcp_payload.hex()
    else:
        tcp_payload = str(tcp_payload)

    analyzed_packets.append(["TCP", tcp_src_port, tcp_dst_port, tcp_payload, packet[scapy.IP].src, packet[scapy.IP].dst])

def analyze_udp(packet):
    """Analyze UDP packets."""
    udp_src_port = packet[scapy.UDP].sport
    udp_dst_port = packet[scapy.UDP].dport
    udp_payload = packet[scapy.UDP].payload
    if isinstance(udp_payload, bytes):
        udp_payload = udp_payload.hex()
    else:
        udp_payload = str(udp_payload)

    analyzed_packets.append(["UDP", udp_src_port, udp_dst_port, udp_payload, packet[scapy.IP].src, packet[scapy.IP].dst])

def analyze_icmp(packet):
    """Analyze ICMP packets."""
    icmp_type = packet[scapy.ICMP].type
    icmp_code = packet[scapy.ICMP].code

    analyzed_packets.append(["ICMP", icmp_type, icmp_code, None, packet[scapy.IP].src, packet[scapy.IP].dst])

def analyze_dns(packet):
    """Analyze DNS packets."""
    dns_query = packet[scapy.DNSQR].qname.decode()
    dns_resp = packet[scapy.DNSRR].rdata.decode()

    analyzed_packets.append(["DNS", dns_query, dns_resp, None, packet[scapy.IP].src, packet[scapy.IP].dst])

def process_packet(packet):
    """Process packets and analyze their contents."""
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        logging.info(f"IP Packet: {ip_src} -> {ip_dst} Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            analyze_tcp(packet)

        elif packet.haslayer(scapy.UDP):
            analyze_udp(packet)

        elif packet.haslayer(scapy.ICMP):
            analyze_icmp(packet)

        elif packet.haslayer(scapy.DNS):
            analyze_dns(packet)

def sniff_packets(duration):
    """Sniff packets for a given duration."""
    start_time = time.time()
    while time.time() - start_time < duration:
        scapy.sniff(prn=process_packet, store=False, timeout=2)

def validate_duration(duration):
    """Validate the duration parameter."""
    if not isinstance(duration, (int, float)) or duration <= 0:
        raise ValueError("Duration must be a positive number.")

# Validate the duration parameter
try:
    duration = float(input("Enter duration (in seconds) to sniff packets: "))
    validate_duration(duration)
except ValueError as e:
    logging.error("Input validation error: " + str(e))
    sys.exit(1)

# Start capturing and analyzing packets for the specified duration
try:
    sniff_packets(duration)
except Exception as e:
    logging.error("An error occurred while sniffing packets: " + str(e))
    sys.exit(1)

# Display analyzed packets in a table
print("\nAnalyzed Packets:")
print(tabulate(analyzed_packets, headers=["Protocol",  "Source IP", "Destination IP", "Source Port", "Destination Port", "Payload"], tablefmt="pretty"))