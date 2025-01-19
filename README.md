# IoT-Traffic-Anomaly-Detection-System
ython Libraries: scapy (for packet capture) numpy (for data processing) sklearn (for anomaly detection with Machine Learning) Dataset (Optional): IoT network traffic datasets for training a machine learning model. Example: CICIDS2017.
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import numpy as np
import threading

# Global variables for traffic features
traffic_data = []
FEATURE_COUNT = 5  # Number of features to extract from each packet

def extract_features(packet):
    """
    Extract features from a network packet.
    """
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)
            if TCP in packet:
                src_port = packet[TCP].sport
            elif UDP in packet:
                src_port = packet[UDP].sport
            else:
                src_port = 0

            return [src_ip, dst_ip, protocol, src_port, length]
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def packet_handler(packet):
    """
    Handle each captured packet and extract features.
    """
    features = extract_features(packet)
    if features:
        traffic_data.append(features)

def start_packet_sniffer(interface="eth0"):
    """
    Start sniffing packets on the specified network interface.
    """
    print(f"Starting packet sniffer on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, store=False)

def train_anomaly_detector(data):
    """
    Train an Isolation Forest model for anomaly detection.
    """
    print("Training anomaly detection model...")
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(data)
    return model

def detect_anomalies(model, data):
    """
    Detect anomalies in the network traffic using the trained model.
    """
    print("Detecting anomalies...")
    predictions = model.predict(data)
    anomalies = [data[i] for i in range(len(predictions)) if predictions[i] == -1]
    return anomalies

def main():
    # Step 1: Start packet sniffing in a separate thread
    sniffer_thread = threading.Thread(target=start_packet_sniffer, args=("eth0",))
    sniffer_thread.daemon = True
    sniffer_thread.start()

    # Step 2: Wait for packets to be captured
    print("Capturing traffic... Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping packet capture...")

    # Step 3: Preprocess traffic data
    print("Processing captured traffic data...")
    numeric_data = np.array([d[3:] for d in traffic_data if len(d) == FEATURE_COUNT])

    # Step 4: Train anomaly detection model
    if len(numeric_data) > 10:  # Ensure we have enough data
        model = train_anomaly_detector(numeric_data)

        # Step 5: Detect anomalies
        anomalies = detect_anomalies(model, numeric_data)
        print(f"Anomalies detected: {len(anomalies)}")
        for anomaly in anomalies:
            print(f"Anomalous Packet: {anomaly}")
    else:
        print("Insufficient data for training.")

if __name__ == "__main__":
    main()
