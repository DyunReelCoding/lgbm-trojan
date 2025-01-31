import numpy as np
import joblib
import scapy.all as scapy
import socket
import urllib.request

# Load the trained LightGBM model
model_path = "lgbm_trojan_model.pkl"
model = joblib.load(model_path)

# Function to extract features from packet data
def extract_features_from_website(pcap_file_path):
    features = {
        'Fwd_Packet_Length_Mean': 0,
        'Bwd_Packet_Length_Mean': 0,
        'Total_Length_of_Bwd_Packets': 0,
        'Flow_Packets_s': 0,
        'Flow_Duration': 0,
        'Flow_IAT_Mean': 0,
        'Fwd_IAT_Mean': 0,
        'Flow_Bytes_s': 0,
        'Fwd_Packets_s': 0,
        'Fwd_IAT_Max': 0,
        'Fwd_Packet_Length_Min': np.inf,
        'Min_Packet_Length': np.inf,
        'Packet_Length_Mean': 0,
        'Fwd_Packet_Length_Std': 0,
        'Fwd_Packet_Length_Max': 0,
        'Total_Length_of_Fwd_Packets': 0,
        'Fwd_IAT_Min': np.inf,
        'Bwd_Packets_s': 0,
        'Flow_IAT_Max': 0,
        'Destination_Port': 0,
        'Bwd_IAT_Min': np.inf,
        'min_seg_size_forward': 0,
        'Bwd_Packet_Length_Min': np.inf,
        'Init_Win_bytes_forward': 0,
        'Init_Win_bytes_backward': 0,
        'Flow_IAT_Min': np.inf,
        'Source_Port': 0,
        'Source_IP': 0,
        'Flow_ID': 0,
        'Destination_IP': 0
    }

    try:
        packets = scapy.rdpcap(pcap_file_path)
        packet_times = []
        forward_lengths = []
        backward_lengths = []
        packet_lengths = []

        for packet in packets:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto

                # Update IP-based features
                if features['Source_IP'] == 0:
                    features['Source_IP'] = hash(src_ip)
                if features['Destination_IP'] == 0:
                    features['Destination_IP'] = hash(dst_ip)

                # Update port-based features for TCP/UDP
                if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                    src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].sport
                    dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport
                    features['Source_Port'] = src_port
                    features['Destination_Port'] = dst_port

                # Update packet lengths
                pkt_len = len(packet)
                packet_lengths.append(pkt_len)
                features['Min_Packet_Length'] = min(features['Min_Packet_Length'], pkt_len)
                features['Fwd_Packet_Length_Min'] = min(features['Fwd_Packet_Length_Min'], pkt_len)
                features['Fwd_Packet_Length_Max'] = max(features['Fwd_Packet_Length_Max'], pkt_len)
                features['Total_Length_of_Fwd_Packets'] += pkt_len

                # Separate forward and backward traffic
                if src_ip == features['Source_IP']:
                    forward_lengths.append(pkt_len)
                else:
                    backward_lengths.append(pkt_len)

                # Update packet times
                packet_times.append(packet.time)

        # Calculate duration
        if len(packet_times) > 1:
            features['Flow_Duration'] = packet_times[-1] - packet_times[0]

        # Calculate means and stats
        features['Fwd_Packet_Length_Mean'] = np.mean(forward_lengths) if forward_lengths else 0
        features['Fwd_Packet_Length_Std'] = np.std(forward_lengths) if forward_lengths else 0
        features['Bwd_Packet_Length_Mean'] = np.mean(backward_lengths) if backward_lengths else 0
        features['Bwd_Packet_Length_Min'] = min(backward_lengths) if backward_lengths else 0
        features['Packet_Length_Mean'] = np.mean(packet_lengths) if packet_lengths else 0

        # Calculate throughput and packet rate
        if features['Flow_Duration'] > 0:
            features['Flow_Bytes_s'] = sum(packet_lengths) / features['Flow_Duration']
            features['Flow_Packets_s'] = len(packet_lengths) / features['Flow_Duration']

        # Inter-arrival time calculations
        iat_differences = np.diff(packet_times)
        if len(iat_differences) > 0:
            features['Flow_IAT_Mean'] = np.mean(iat_differences)
            features['Flow_IAT_Max'] = np.max(iat_differences)
            features['Flow_IAT_Min'] = np.min(iat_differences)
        else:
            features['Flow_IAT_Mean'] = features['Flow_IAT_Max'] = features['Flow_IAT_Min'] = 0

        return np.array([features[feature] for feature in features]).reshape(1, -1)
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Function to classify website traffic
def classify_website(pcap_file_path):
    features = extract_features_from_website(pcap_file_path)
    if features is not None:
        prediction = model.predict(features)
        prediction_probabilities = model.predict_proba(features)

        print(f"Prediction: {prediction[0]} (1: Trojan, 0: Safe)")
        print(f"Prediction Probabilities: {prediction_probabilities}")

        if prediction_probabilities[0][0] > prediction_probabilities[0][1]:
            print("Warning: This website traffic is classified as Trojan.")
        else:
            print("Safe: This website traffic is classified as safe.")

# Function to capture packets for a given URL
def capture_website_traffic(url, capture_duration=10):
    print(f"Starting packet capture for {url}...")
    pcap_file = "website_traffic.pcap"  # Output file for the capture

    # Resolve domain to IP
    try:
        ip_address = socket.gethostbyname(url.split("//")[-1].split("/")[0])  # Resolve IP from the URL
        print(f"Resolved {url} to IP address: {ip_address}")

        # Open the website URL to simulate traffic with User-Agent header
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        req = urllib.request.Request(url, headers=headers)
        urllib.request.urlopen(req)  # Open the website with custom headers to simulate browser traffic
        print(f"Opening {url} to simulate traffic...")

        # Use scapy to capture the packets during the website interaction
        scapy.sniff(timeout=capture_duration, prn=lambda x: x.summary(), filter=f"host {ip_address}", store=True)
        scapy.wrpcap(pcap_file, scapy.sniff(timeout=capture_duration, filter=f"host {ip_address}"))  # Save packets to .pcap file
        print(f"Packet capture completed and saved to {pcap_file}.")

        return pcap_file
    except Exception as e:
        print(f"Error capturing traffic: {e}")
        return None

# Example usage
url = "https://chatgpt.com/c/67999a4d-e898-800d-80b4-9a20e704b766"
pcap_file = capture_website_traffic(url)
if pcap_file:
    classify_website(pcap_file)

