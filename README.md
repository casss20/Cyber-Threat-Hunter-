📡 Cyber Threat Hunter
A machine learning–powered tool that captures, analyzes, and classifies network packets in real time. Designed for cybersecurity research and protocol prediction using live sniffed traffic.

📘 What Is This Project?
Cyber Threat Hunter is a Python-based terminal application that uses a trained Random Forest classifier to identify and classify network packet protocols (e.g., TCP, UDP, ICMP) in live network streams. It features:

Live packet sniffing using Scapy
Real-time protocol classification via AI
A responsive terminal dashboard using Rich
Automatic logging of suspicious TCP/UDP traffic
Support for custom BPF filters (e.g., port 80, icmp)
It serves as a research tool and educational showcase of integrating machine learning with network security analysis.

🧠 Key Features
✅ Live Network Capture with Scapy
✅ AI-Powered Protocol Detection
✅ Rich Terminal Dashboard
✅ Suspicious Packet Logging
✅ Protocol Mapping Automation
✅ Evaluation Suite with ROC, Confusion Matrix, Accuracy Reports
🏗️ Project Structure
CyberThreatHunter/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── outputs/                        # Model, logs, and processed datasets
│   ├── random_forest_model.pkl
│   ├── suspicious_packets_log.txt
│   └── packet_log_with_protocols.csv
├── scripts/
│   ├── train_model.py              # Trains the AI model
│   ├── evaluate_model.py          # Performance metrics + visuals
│   ├── live_sniffer_predictor.py  # Live dashboard & sniffer tool
│   └── protocol_mapper.py         # Maps protocol numbers to names
🔧 Setup Instructions
# 1. Clone the repository
git clone https://github.com/yourusername/CyberThreatHunter.git
cd CyberThreatHunter

# 2. Set up Python environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt
🚀 Usage
Train the Model (Run first)
python scripts/train_model.py
Map Protocols from Raw CSV
python scripts/protocol_mapper.py
Launch Live Packet Prediction
python scripts/live_sniffer_predictor.py
Evaluate Model Performance
python scripts/evaluate_model.py
📊 Sample Output (Live Dashboard)
🚀 CyberHunter Live Dashboard

Metric             Count     Rate
--------------------------------------
Total Packets      2000      -
TCP Packets        1400     70.0%
UDP Packets         400     20.0%
ICMP Packets        100      5.0%
Other Protocols     100      5.0%
🧪 Model Evaluation Metrics
📈 Classification report
🎯 Confusion matrix
🔍 ROC-AUC curves (multiclass)
✅ Accuracy by protocol
📚 Academic Use Cases
This tool is suitable for:

Network security labs
Intrusion detection research
Machine learning model deployment
Applied cybersecurity analytics courses
🛡️ Author
Mr. Casseus
🎓 B.Sc. Computer Science (UCF)
🔐 Cybersecurity Minor | AI Researcher | Aspiring Threat Analyst
