from flask import Flask, request, jsonify
import numpy as np
import joblib
import scapy.all as scapy
import socket

app = Flask(__name__)

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
                pkt_len = len(packet)
                packet_lengths.append(pkt_len)
                features['Min_Packet_Length'] = min(features['Min_Packet_Length'], pkt_len)
                features['Fwd_Packet_Length_Min'] = min(features['Fwd_Packet_Length_Min'], pkt_len)
                features['Fwd_Packet_Length_Max'] = max(features['Fwd_Packet_Length_Max'], pkt_len)
                features['Total_Length_of_Fwd_Packets'] += pkt_len

                if src_ip == features['Source_IP']:
                    forward_lengths.append(pkt_len)
                else:
                    backward_lengths.append(pkt_len)

                packet_times.append(packet.time)

        if len(packet_times) > 1:
            features['Flow_Duration'] = packet_times[-1] - packet_times[0]

        features['Fwd_Packet_Length_Mean'] = np.mean(forward_lengths) if forward_lengths else 0
        features['Bwd_Packet_Length_Mean'] = np.mean(backward_lengths) if backward_lengths else 0
        features['Packet_Length_Mean'] = np.mean(packet_lengths) if packet_lengths else 0

        return np.array([features[feature] for feature in features]).reshape(1, -1)
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Route to classify website traffic
@app.route("/predict", methods=["POST"])
def classify_website():
    data = request.get_json()
    url = data.get("url")
    capture_duration = data.get("duration", 10)

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        app.logger.info(f"Starting packet capture for {url}...")
        
        # Resolve IP
        domain = url.split("//")[-1].split("/")[0]
        try:
            ip_address = socket.gethostbyname(domain)
            app.logger.info(f"Resolved {url} to IP address: {ip_address}")
        except socket.gaierror:
            app.logger.error(f"Could not resolve {url} to an IP address.")
            return jsonify({"error": f"Could not resolve {url} to an IP address."}), 404
        
        # Capture traffic
        pcap_file = f"{domain}_traffic.pcap"
        app.logger.info(f"Opening {url} to simulate traffic...")
        packets = scapy.sniff(timeout=capture_duration, filter=f"host {ip_address}", store=True)
        
        if not packets:
            app.logger.error(f"No packets were captured for {url}.")
            return jsonify({"error": f"No packets were captured for {url}. Ensure the website is accessible and traffic is present."}), 500
        
        scapy.wrpcap(pcap_file, packets)
        app.logger.info(f"Packet capture completed and saved to {pcap_file}.")
        
        # Extract features and classify
        features = extract_features_from_website(pcap_file)
        if features is not None:
            prediction = model.predict(features)
            prediction_probabilities = model.predict_proba(features)
            
            if prediction_probabilities[0][0] > prediction_probabilities[0][1]:
                result = "Warning: This website traffic is classified as Trojan."
            else:
                result = "Safe: This website traffic is classified as safe."
            
            app.logger.info(f"Prediction: {result}")
            return jsonify({
                "url": url,
                "prediction": result,
                "probabilities": prediction_probabilities.tolist()
            })

        app.logger.error("Feature extraction failed.")
        return jsonify({"error": "Feature extraction failed"}), 500
    except Exception as e:
        app.logger.error(f"Error during processing: {e}")
        return jsonify({"error": f"Error during processing: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)