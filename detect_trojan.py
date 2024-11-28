import numpy as np
import pandas as pd
from scapy.all import sniff, TCP
import joblib
from scapy.config import conf
from scapy.all import sniff
import socket

conf.use_pcap = True

def packet_callback(packet):
    print(packet.summary())

sniff(count=10, prn=packet_callback)

def resolve_url_to_ip(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        print(f"Could not resolve {url} to an IP address.")
        return None

# Extract all 80 features
def extract_all_features(packets):
    features = {}

    # Initialize accumulators and counters
    fwd_packets = []
    bwd_packets = []
    fwd_packet_lengths = []
    bwd_packet_lengths = []
    packet_lengths = []
    active_times = []
    flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "CWE": 0, "ECE": 0}
    
    total_fwd_bytes = 0
    total_bwd_bytes = 0
    total_fwd_pkts = 0
    total_bwd_pkts = 0

    flow_start_time = packets[0].time if packets else 0
    prev_packet_time = flow_start_time

    # Process packets
    for packet in packets:
        if not packet.haslayer(TCP):
            continue  # Only analyze TCP packets

        # Determine direction
        direction = "fwd" if packet[TCP].sport < packet[TCP].dport else "bwd"

        # Compute lengths and counts
        pkt_len = len(packet)
        packet_lengths.append(pkt_len)
        if direction == "fwd":
            fwd_packets.append(packet)
            fwd_packet_lengths.append(pkt_len)
            total_fwd_bytes += pkt_len
            total_fwd_pkts += 1
        else:
            bwd_packets.append(packet)
            bwd_packet_lengths.append(pkt_len)
            total_bwd_bytes += pkt_len
            total_bwd_pkts += 1

        # Time features
        current_time = packet.time
        if prev_packet_time:
            active_times.append(current_time - prev_packet_time)
        prev_packet_time = current_time

        # Flags
        tcp_flags = packet[TCP].flags
        flags["FIN"] += tcp_flags.F
        flags["SYN"] += tcp_flags.S
        flags["RST"] += tcp_flags.R
        flags["PSH"] += tcp_flags.P
        flags["ACK"] += tcp_flags.A
        flags["URG"] += tcp_flags.U

    # Flow Duration
    features["Flow Duration"] = (packets[-1].time - flow_start_time) if len(packets) > 1 else 0

    # Packet Counts
    features["Total Fwd Packets"] = len(fwd_packets)
    features["Total Backward Packets"] = len(bwd_packets)

    # Packet Lengths
    features["Total Length of Fwd Packets"] = total_fwd_bytes
    features["Total Length of Bwd Packets"] = total_bwd_bytes
    features["Fwd Packet Length Max"] = max(fwd_packet_lengths, default=0)
    features["Fwd Packet Length Min"] = min(fwd_packet_lengths, default=0)
    features["Fwd Packet Length Mean"] = np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0
    features["Fwd Packet Length Std"] = np.std(fwd_packet_lengths) if fwd_packet_lengths else 0
    features["Bwd Packet Length Max"] = max(bwd_packet_lengths, default=0)
    features["Bwd Packet Length Min"] = min(bwd_packet_lengths, default=0)
    features["Bwd Packet Length Mean"] = np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0
    features["Bwd Packet Length Std"] = np.std(bwd_packet_lengths) if bwd_packet_lengths else 0

    # Flow Rates
    features["Flow Bytes/s"] = (total_fwd_bytes + total_bwd_bytes) / features["Flow Duration"] if features["Flow Duration"] > 0 else 0
    features["Flow Packets/s"] = len(packets) / features["Flow Duration"] if features["Flow Duration"] > 0 else 0

    # Inter-Arrival Times (IAT)
    features["Flow IAT Mean"] = np.mean(active_times) if active_times else 0
    features["Flow IAT Std"] = np.std(active_times) if active_times else 0
    features["Flow IAT Max"] = max(active_times, default=0)
    features["Flow IAT Min"] = min(active_times, default=0)

    # Flags
    features["FIN Flag Count"] = flags["FIN"]
    features["SYN Flag Count"] = flags["SYN"]
    features["RST Flag Count"] = flags["RST"]
    features["PSH Flag Count"] = flags["PSH"]
    features["ACK Flag Count"] = flags["ACK"]
    features["URG Flag Count"] = flags["URG"]
    features["CWE Flag Count"] = flags["CWE"]
    features["ECE Flag Count"] = flags["ECE"]

    # Packet Statistics
    features["Min Packet Length"] = min(packet_lengths, default=0)
    features["Max Packet Length"] = max(packet_lengths, default=0)
    features["Packet Length Mean"] = np.mean(packet_lengths) if packet_lengths else 0
    features["Packet Length Std"] = np.std(packet_lengths) if packet_lengths else 0
    features["Packet Length Variance"] = np.var(packet_lengths) if packet_lengths else 0

    # Derived Features
    features["Down/Up Ratio"] = len(fwd_packets) / len(bwd_packets) if len(bwd_packets) > 0 else 0
    features["Average Packet Size"] = np.mean(packet_lengths) if packet_lengths else 0
    features["Avg Fwd Segment Size"] = np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0
    features["Avg Bwd Segment Size"] = np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0

    # Subflows
    features["Subflow Fwd Packets"] = total_fwd_pkts
    features["Subflow Bwd Packets"] = total_bwd_pkts
    features["Subflow Fwd Bytes"] = total_fwd_bytes
    features["Subflow Bwd Bytes"] = total_bwd_bytes

    # Window Sizes
    features["Init_Win_bytes_forward"] = fwd_packets[0][TCP].window if fwd_packets else 0
    features["Init_Win_bytes_backward"] = bwd_packets[0][TCP].window if bwd_packets else 0

    # Active/Idle Features
    features["Active Mean"] = np.mean(active_times) if active_times else 0
    features["Active Std"] = np.std(active_times) if active_times else 0
    features["Active Max"] = max(active_times, default=0)
    features["Active Min"] = min(active_times, default=0)

    # Idle Times (Compute from time gaps between flows)
    idle_times = [active_times[i + 1] - active_times[i] for i in range(len(active_times) - 1)]
    features["Idle Mean"] = np.mean(idle_times) if idle_times else 0
    features["Idle Std"] = np.std(idle_times) if idle_times else 0
    features["Idle Max"] = max(idle_times, default=0)
    features["Idle Min"] = min(idle_times, default=0)

    return features

# Load trained LightGBM model
model = joblib.load("./lgbm_model.pkl")

# URL for testing
url = "wikipedia.org"
ip = resolve_url_to_ip(url)

if ip:
    print(f"Resolved {url} to {ip}. Capturing packets...")
    packets = sniff(count=10, filter=f"tcp port 443 and ip host {ip}", prn=packet_callback)
    
    extracted_features = extract_all_features(packets)
    
    # Convert features to DataFrame
    feature_df = pd.DataFrame([extracted_features])
    
    # Make prediction
    prediction = model.predict(feature_df)
    print("Trojan" if prediction[0] == 1 else "Safe")
else:
    print("Failed to analyze the URL. Please check the URL and try again.")
