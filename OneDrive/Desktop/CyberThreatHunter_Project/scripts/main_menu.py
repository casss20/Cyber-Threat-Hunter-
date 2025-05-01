"""
Cyber Threat Hunter - Main Control Menu

Description:
-------------
This script serves as the main menu launcher for all CyberHunter tools.
It allows the user to map protocols, train AI models, predict protocols manually, and run the live sniffer — all from one place.

1. Map Protocols:
   → Map protocol numbers to human-readable names and save clean dataset.

2. Train AI Model:
   → Train a Random Forest AI model to recognize packet types.

3. Predict Protocols Manually:
   → Manually input protocol numbers and get instant predictions.

4. Live Packet Sniffer & Predictor:
   → Capture live network traffic, predict protocol types in real-time, and log important packets.

5. Exit:
   → Close the CyberHunter system safely.

Libraries Used:
-------------
- os
- colorama

Author:
-------------
Mr. Casseus 🚀 (Future Cyber AI Engineer)

Date: 2025-04-28
"""

# Import necessary libraries
import os   # To run other Python scripts from inside your menu
from colorama import Fore, Style, init

# Initialize colorama
init()

# Function to show the banner
def show_banner():
    print(Fore.CYAN + r"""
   ____            _              _   _           _            
  / ___| _   _ ___| |_ ___ _ __   | | | | ___  ___| |_ ___ _ __ 
  \___ \| | | / __| __/ _ \ '__|  | |_| |/ _ \/ __| __/ _ \ '__|
   ___) | |_| \__ \ ||  __/ |     |  _  |  __/\__ \ ||  __/ |   
  |____/ \__, |___/\__\___|_|     |_| |_|\___||___/\__\___|_|   
          |___/                                                 
    Cyber Threat Hunter - AI Powered Packet Analysis
    """ + Style.RESET_ALL)

# Function to show the main menu
def show_menu():
    print("\n" + "="*50)
    print("🛡  CyberHunter Main Menu")
    print("="*50)
    print("""
1. Map Protocols
   → Map protocol numbers to readable protocol names (TCP, UDP, etc.)

2. Train AI Model
   → Train Random Forest AI model on packet data.

3. Predict Protocols Manually
   → Type protocol numbers and get instant AI predictions.

4. Live Packet Sniffer & Predictor
   → Capture live traffic, predict protocol types, and log important packets.
          
5. Evaluate Model 
   → Show the graphic image to the packet capture
         

6. Exit
   → Safely close the CyberHunter system.
""")
    print("="*50)

# Run the program
show_banner()

while True:
    show_menu()
    choice = input("Enter your choice (1-6): ")

    if choice == "1":
        os.system("python scripts\\map_protocols.py")
    elif choice == "2":
        os.system("python scripts\\split_and_train.py")
    elif choice == "3":
        os.system("python scripts\\predict_new_packets.py")
    elif choice == "4":
        os.system("python scripts\\live_sniffer_predictor.py")
    elif choice == "5":
        os.system("python scripts\\evaluate_model.py")
    elif choice == "6":
        print(Fore.YELLOW + "Exiting CyberHunter... Goodbye!" + Style.RESET_ALL)
        break
    else:
        print(Fore.RED + "Invalid choice. Please enter a number between 1 and 6." + Style.RESET_ALL)