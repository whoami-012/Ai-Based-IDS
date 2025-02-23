from scapy.all import sniff, IP, TCP, UDP

# Packet processing function
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Check if the packet is TCP or UDP
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[TCP] {src_ip}:{sport} -> {dst_ip}:{dport}")

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[UDP] {src_ip}:{sport} -> {dst_ip}:{dport}")

        else:
            print(f"[IP] {src_ip} -> {dst_ip} | Protocol: {proto}")

# Start sniffing packets
print("Sniffing packets... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
