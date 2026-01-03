from scapy.all import rdpcap, IP, TCP, UDP, ICMP

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)

    print("\n📡 Packet Analysis Started\n")

    for i, packet in enumerate(packets, start=1):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            if TCP in packet:
                protocol = "TCP"
                payload = bytes(packet[TCP].payload)[:50]
            elif UDP in packet:
                protocol = "UDP"
                payload = bytes(packet[UDP].payload)[:50]
            elif ICMP in packet:
                protocol = "ICMP"
                payload = b""
            else:
                protocol = "OTHER"
                payload = b""

            print(f"Packet {i}")
            print(f" Source IP      : {src}")
            print(f" Destination IP : {dst}")
            print(f" Protocol       : {protocol}")
            print(f" Payload        : {payload}")
            print("-" * 40)


# ---------- MAIN ----------
pcap_name = input("Enter PCAP file name (example: capture.pcap): ")

try:
    analyze_packets(pcap_name)
except FileNotFoundError:
    print("❌ PCAP file not found!")
