from scapy.all import sniff, IP
import pandas as pd
import datetime

packets_data = []

def process_packet(packet):
    if packet.haslayer(IP):
        pkt = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto
        }
        packets_data.append(pkt)

print("[*] Capturing packets... (Press Ctrl+C to stop)")
sniff(filter="ip", prn=process_packet, count=100)

# Save to CSV
df = pd.DataFrame(packets_data)
df.to_csv("packet_log.csv", index=False)

print("[✓] Packet capture complete. Data saved to 'packet_log.csv'")
