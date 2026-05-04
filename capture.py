from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = ""
        info = ""

        if TCP in packet:
            protocol = "TCP"
            info = f"Port {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            info = f"Port {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"
            info = "Ping packet"
        else:
            protocol = "OTHER"
            info = ""

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {protocol} | {ip_src} → {ip_dst} | {info}")

print("Starting packet capture... Press Ctrl+C to stop\n")
sniff(prn=analyze_packet, store=False, count=50)