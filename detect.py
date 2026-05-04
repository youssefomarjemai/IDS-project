import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sqlite3
import os

# Load the trained model and encoders
print("Loading model...")
model = joblib.load('models/ids_model.pkl')
encoders = joblib.load('models/encoders.pkl')
print("Model loaded successfully!")

# Set up the database to store alerts
def setup_database():
    conn = sqlite3.connect('logs/alerts.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            prediction TEXT,
            src_bytes INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def save_alert(timestamp, src_ip, dst_ip, protocol, src_port, dst_port, prediction, src_bytes):
    conn = sqlite3.connect('logs/alerts.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, prediction, src_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, prediction, src_bytes))
    conn.commit()
    conn.close()

def extract_features(packet):
    if not IP in packet:
        return None

    # Extract basic features from packet
    protocol = 0
    src_port = 0
    dst_port = 0
    src_bytes = len(packet)

    if TCP in packet:
        protocol = 'tcp'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flag = 'SF'
    elif UDP in packet:
        protocol = 'udp'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flag = 'SF'
    elif ICMP in packet:
        protocol = 'icmp'
        flag = 'SF'
    else:
        return None

    # Build feature row matching NSL-KDD columns
    features = {
        'duration': 0,
        'protocol_type': protocol,
        'service': 'http',
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': 0,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 1,
        'srv_count': 1,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0,
        'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 1,
        'dst_host_srv_count': 1,
        'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 1.0,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }

    return features

def analyze_packet(packet):
    if not IP in packet:
        return

    features = extract_features(packet)
    if features is None:
        return

    # Encode categorical features
    df = pd.DataFrame([features])
    for col in ['protocol_type', 'service', 'flag']:
        try:
            df[col] = encoders[col].transform(df[col])
        except:
            df[col] = 0

    # Make prediction
    prediction = model.predict(df)[0]

    # Get packet info
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP"
    src_port = features.get('src_bytes', 0)
    dst_port = 0
    src_bytes = features['src_bytes']

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Display result
    status = "⚠️  ATTACK" if prediction == 'attack' else "✅ NORMAL"
    print(f"[{timestamp}] {status} | {protocol} | {src_ip} → {dst_ip} | Bytes: {src_bytes}")

    # Save to database
    save_alert(timestamp, src_ip, dst_ip, protocol, src_port, dst_port, prediction, src_bytes)

# Main
setup_database()
print("\nStarting real-time detection... Press Ctrl+C to stop\n")
print(f"{'Time':<10} {'Status':<15} {'Protocol':<8} {'Source':<20} {'Destination':<20} {'Bytes'}")
print("-" * 85)
sniff(prn=analyze_packet, store=False, count=30)
print("\nDetection complete! Alerts saved to logs/alerts.db")