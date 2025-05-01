"""
Cyber Threat Hunter - Manual Protocol Prediction Tool

Description:
-------------
This script allows a user to manually input protocol numbers (e.g., 6, 17),
predicts the protocol name (e.g., TCP, UDP) using a trained AI model (Random Forest),
and displays the results clearly.

Main Features:
-------------
- Accepts user input of multiple protocol numbers.
- Predicts protocol names instantly using the trained AI model.
- Displays all predictions in a clean, readable format.

Libraries Used:
-------------
- pandas
- joblib

Author:
-------------
Mr. Casseus 🚀 (Future Cyber AI Engineer)

Date: 2025-04-28
"""
# 1. Import necessary libraries
import pandas as pd
import joblib
import os
import sys
from colorama import Fore, Style, init  # <-- Add color support

# Initialize colorama
init()

# 2. Define the model path correctly
base_dir = os.path.dirname(os.path.dirname(__file__))  # Move up to project root
model_path = os.path.join(base_dir, 'outputs', 'random_forest_model.pkl')

# 3. Check if the AI model exists
if not os.path.exists(model_path):
    print("\n" + Fore.RED + "="*50 + Style.RESET_ALL)
    print(Fore.RED + "⚠️  Model not found! You must train it first." + Style.RESET_ALL)
    print(Fore.YELLOW + "➡️  Please run option 2 (Train AI Model) from the main menu." + Style.RESET_ALL)
    print(Fore.RED + "="*50 + "\n" + Style.RESET_ALL)
    sys.exit(1)  # Exit cleanly if model missing

# 4. Load the trained AI model
model = joblib.load(model_path)

# 5. Show reference table of protocol numbers
print(Fore.YELLOW + "\nAvailable Protocol Numbers:" + Style.RESET_ALL)
print(Fore.CYAN + "-"*35)
protocol_reference = {
    1:  'ICMP',
    2:  'IGMP',
    6:  'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    89: 'OSPF',
    132: 'SCTP'
}
for number, name in protocol_reference.items():
    print(Fore.YELLOW + f"{number}".ljust(5) + Fore.MAGENTA + "➔ " + Fore.GREEN + name)
print(Fore.CYAN + "-"*35 + Style.RESET_ALL)
print(Fore.CYAN + "[?] Enter protocol numbers separated by commas (example: 6,17):" + Style.RESET_ALL)
user_input = input(Fore.GREEN + ">>> " + Style.RESET_ALL)

# 6. Convert user input into a list of integers
proto_list = [int(x.strip()) for x in user_input.split(",")]

# 7. Prepare the input data in DataFrame format
new_data = pd.DataFrame({'proto': proto_list})

# 8. Predict the protocol names
predictions = model.predict(new_data)

# 9. Display the prediction results nicely
print(Fore.GREEN + "\n[✓] Prediction Results:" + Style.RESET_ALL)
for proto, prediction in zip(new_data['proto'], predictions):
    print(Fore.YELLOW + f"Protocol Number {proto}" + Fore.CYAN + " ➔ " + Fore.MAGENTA + f"Predicted Protocol Name: {prediction}" + Style.RESET_ALL)
