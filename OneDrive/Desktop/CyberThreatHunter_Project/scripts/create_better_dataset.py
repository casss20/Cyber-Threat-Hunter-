# 1. Import necessary libraries
import pandas as pd
import os

# 2. Define the correct protocol mappings
protocol_data = {
    'proto': [1, 2, 6, 17, 47, 50, 51, 89, 132],
    'proto_name': ['ICMP', 'IGMP', 'TCP', 'UDP', 'GRE', 'ESP', 'AH', 'OSPF', 'SCTP']
}

# 3. Create the DataFrame
df = pd.DataFrame(protocol_data)

# 4. Create the outputs/ folder if it doesn't exist
if not os.path.exists('outputs'):
    os.makedirs('outputs')

# 5. Save the DataFrame into a CSV file
df.to_csv('outputs/packet_log_with_protocols.csv', index=False)

print("[✓] Better dataset created and saved successfully at 'outputs/packet_log_with_protocols.csv'!")
