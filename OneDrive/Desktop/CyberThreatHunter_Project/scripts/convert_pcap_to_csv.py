"""
This script converts a .pcap file (captured using Wireshark or tcpdump)
into a CSV file with basic fields: timestamp, src, dst, proto.
"""

import pandas as pd
from scapy.all import rdpcap, IP
import os

# 1. Ask the user for the .pcap file path
pcap_path = input("Enter path to .pcap file (example: data/myfile.pcap): ").strip()

# 2. Make sure the path is valid
if not os.path.exists(pcap_path):
    print("❌ File does not exist!")
    exit()

# 3. Read packets from .pcap file
packets = rdpcap(pcap_path)
print(f"[✓] Loaded {len(packets)} packets")

# 4. Extract fields
packet_data = []
for pkt in packets:
    if IP in pkt:
        packet_data.append({
            'timestamp': pkt.time,
            'src': pkt[IP].src,
            'dst': pkt[IP].dst,
            'proto': pkt[IP].proto
        })

# 5. Create DataFrame
df = pd.DataFrame(packet_data)

# 6. Save to CSV
output_path = os.path.join("outputs", "converted_packet_log.csv")
df.to_csv(output_path, index=False)
print(f"[✓] CSV saved at: {output_path}")
