import scapy.all as scapy
import pandas as pd
import joblib
import numpy as np
import tkinter as tk
from tkinter import messagebox

# Load AI model
model = joblib.load("ids_model.pkl")

# Dynamically load expected features
expected_features = list(pd.read_csv("preprocessed_data.csv").drop("label", axis=1).columns)

# Log file setup
log_file = "detected_attacks.log"

# Load whitelist IPs
whitelist_file = "whitelist.txt"
try:
    with open(whitelist_file, "r") as f:
        whitelisted_ips = set(line.strip() for line in f.readlines() if line.strip())
except FileNotFoundError:
    whitelisted_ips = set()

# Function to show an alert popup
def show_alert(message):
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning("INTRUSION ALERT", message)

# Function to analyze packets
def analyze_packet(packet):
    if not packet.haslayer(scapy.IP):
        return  

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst

    # Check if either IP is whitelisted
    if src_ip in whitelisted_ips or dst_ip in whitelisted_ips:
        print(f"🛑 Skipping whitelisted IP: {src_ip} -> {dst_ip}")
        return  

    protocol = packet[scapy.IP].proto
    src_port = packet.sport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
    dst_port = packet.dport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
    packet_length = len(packet)

    # Construct DataFrame with correct feature order
    packet_data = pd.DataFrame([[src_port, dst_port, packet_length, protocol]], columns=["src_port", "dst_port", "packet_length", "protocol"])
    packet_data = packet_data.reindex(columns=expected_features, fill_value=0)

    # Convert to NumPy array to avoid feature mismatch warning
    packet_array = packet_data.to_numpy()

    # Predict attack or normal
    prediction = model.predict(packet_array)[0]

    # Log and Alert
    log_entry = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {protocol} | Length: {packet_length} | Threat: {prediction}\n"
    print(log_entry)
    with open(log_file, "a") as log:
        log.write(log_entry)

    if prediction == "attack":
        show_alert(f"Potential attack from {src_ip} to {dst_ip}!")

# Function to analyze a PCAP file
def analyze_pcap(file_path):
    packets = scapy.rdpcap(file_path)
    print(f"📂 Analyzing {len(packets)} packets from {file_path}...")
    for packet in packets:
        analyze_packet(packet)

# Function to analyze live traffic
def analyze_live():
    scapy.sniff(prn=analyze_packet, store=False)

# Main menu
def main():
    choice = input("Choose (1) Live Traffic or (2) PCAP File: ")
    if choice == "1":
        analyze_live()
    elif choice == "2":
        analyze_pcap(input("Enter PCAP file path: "))
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
