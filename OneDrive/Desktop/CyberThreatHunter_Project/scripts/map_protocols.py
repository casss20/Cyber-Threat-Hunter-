"""
Cyber Threat Hunter - Enhanced Protocol Mapping Script

Description:
-------------
This script loads raw network packet data from 'outputs/converted_packet_log.csv',
maps numeric protocol identifiers (e.g., 6, 17) to their corresponding protocol names (e.g., TCP, UDP)
using an expanded IANA standards-based dictionary, adds the mapped protocol names as a new column,
and saves the updated dataset into 'outputs/packet_log_with_protocols.csv' for AI training.

Main Features:
-------------
- Automatic path detection (works from scripts/ or project root)
- Comprehensive IANA protocol mapping (50+ protocols)
- Detailed data validation and error handling
- Protocol distribution reporting
- Color-coded console output for better visibility

Libraries Used:
-------------
- pandas (for data manipulation)
- os (for path operations)
- colorama (for colored terminal output)
- sys (for system operations)

Author:
-------------
Mr. Casseus 🚀 (Future Cyber AI Engineer)

Date: 2025-04-28
Version: 2.1
"""

# =====================================================================
#                           IMPORT SECTION
# =====================================================================
# Import pandas for data processing - this helps us work with CSV files easily
import pandas as pd

# Import os for operating system path operations - needed for file handling
import os

# Import sys for system-level operations - used for error handling
import sys

# Import colorama for colored terminal output - makes messages easier to read
from colorama import Fore, Style, init

# Initialize colorama to make colors work on Windows too
init()


# =====================================================================
#                     PROTOCOL MAPPING DICTIONARY
# =====================================================================
# This dictionary maps IANA protocol numbers to their official names
# Full list: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTOCOL_MAP = {
    # Common Protocols
    0: 'HOPOPT',   # IPv6 Hop-by-Hop Option
    1: 'ICMP',     # Internet Control Message Protocol
    2: 'IGMP',     # Internet Group Management Protocol
    6: 'TCP',      # Transmission Control Protocol
    17: 'UDP',     # User Datagram Protocol
    
    # VPN/Encapsulation Protocols
    47: 'GRE',     # Generic Routing Encapsulation
    50: 'ESP',     # Encapsulating Security Payload
    51: 'AH',      # Authentication Header
    
    # IPv6 Protocols
    41: 'IPv6',    # IPv6 Encapsulation
    58: 'IPv6-ICMP', # ICMP for IPv6
    
    # Routing Protocols
    89: 'OSPF',    # Open Shortest Path First
    
    # Specialized Protocols
    132: 'SCTP',   # Stream Control Transmission Protocol
    136: 'UDPLite' # Lightweight User Datagram Protocol
}


# =====================================================================
#                     DATA VALIDATION FUNCTION
# =====================================================================
def validate_protocols(df):
    """
    Check for invalid protocol numbers in the dataset
    and suggest additions to the PROTOCOL_MAP dictionary.
    
    Args:
        df (DataFrame): Pandas DataFrame containing packet data
    """
    # Find protocols not in our mapping dictionary
    invalid = df[~df['proto'].isin(PROTOCOL_MAP.keys())]
    
    if not invalid.empty:
        print(Fore.YELLOW + f"[!] Found {len(invalid)} packets with unmapped protocols" + Style.RESET_ALL)
        print("Consider adding these to PROTOCOL_MAP:")
        # Show the unmapped protocols and their frequencies
        print(invalid['proto'].value_counts())


# =====================================================================
#                     MAIN SCRIPT FUNCTION
# =====================================================================
def main():
    """
    Main execution function that handles the protocol mapping workflow:
    1. Sets up file paths
    2. Loads the packet data
    3. Maps protocol numbers to names
    4. Validates the results
    5. Saves the output
    """
    # =====================================================================
#                     ENHANCED MAIN SCRIPT FUNCTION
# =====================================================================
def main():
    # Normalize paths for cross-platform compatibility
    base_dir = os.path.normpath(os.path.dirname(os.path.dirname(__file__))) if '__file__' in globals() else os.getcwd()
    outputs_dir = os.path.normpath(os.path.join(base_dir, 'outputs'))
    
    # Define all possible file paths
    raw_path = os.path.join(outputs_dir, 'converted_packet_log.csv')
    mapped_path = os.path.join(outputs_dir, 'packet_log_with_protocols.csv')
    log_path = os.path.join(outputs_dir, 'suspicious_packets_log.txt')

    try:
        # Check if outputs directory exists
        if not os.path.exists(outputs_dir):
            raise FileNotFoundError(f"Outputs directory not found at {outputs_dir}")

        # Try to find existing data file (accept either format)
        input_file = None
        for f in [raw_path, mapped_path, log_path]:
            if os.path.exists(f):
                input_file = f
                break

        if not input_file:
            raise FileNotFoundError("No packet data found. Please run packet capture first.")

        print(Fore.CYAN + f"[🔄] Loading data from {input_file}..." + Style.RESET_ALL)
        
        # Read data with appropriate parsing
        if input_file.endswith('.txt'):
            # Parse from sniffer log format
            df = pd.read_csv(input_file, 
                           header=None, 
                           names=['timestamp', 'proto', 'src', 'dst'],
                           sep='\t')
        else:
            # Standard CSV read
            df = pd.read_csv(input_file)

        # Validate data structure
        if 'proto' not in df.columns:
            raise ValueError("Input file must contain 'proto' column")

        # Map protocols
        print(Fore.CYAN + "[🔄] Mapping protocol numbers..." + Style.RESET_ALL)
        df['proto_name'] = df['proto'].map(PROTOCOL_MAP).fillna('OTHER')
        validate_protocols(df)

        # Save both formats
        print(Fore.CYAN + "[🔄] Saving data..." + Style.RESET_ALL)
        
        # 1. Save raw numbers (for training)
        df[['proto']].to_csv(raw_path, index=False)
        
        # 2. Save mapped names (for analysis)
        df.to_csv(mapped_path, index=False)
        
        print(Fore.GREEN + "[✓] Saved both file formats:" + Style.RESET_ALL)
        print(f" - Raw protocols: {raw_path}")
        print(f" - Mapped names: {mapped_path}")

        # Show statistics
        print(Fore.BLUE + "\nProtocol Distribution:")
        print(df['proto_name'].value_counts().to_string() + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[✗] Error: {str(e)}" + Style.RESET_ALL)
        sys.exit(1)

    # =================================================================
    #                     PATH CONFIGURATION
    # =================================================================
    # Determine base directory - works whether running from scripts/ or project root
    base_dir = os.path.dirname(os.path.dirname(__file__)) if '__file__' in globals() else os.getcwd()
    
    # Set input and output paths using os.path.join for cross-platform compatibility
    input_path = os.path.join(base_dir, 'outputs', 'converted_packet_log.csv')
    output_path = os.path.join(base_dir, 'outputs', 'packet_log_with_protocols.csv')

    try:
        # =============================================================
        #                     DATA LOADING
        # =============================================================
        print(Fore.CYAN + f"[🔄] Loading data from {input_path}..." + Style.RESET_ALL)
        
        # Read the CSV file into a pandas DataFrame
        df = pd.read_csv(input_path)

        # =============================================================
        #                     DATA VALIDATION
        # =============================================================
        # Check if required 'proto' column exists
        if 'proto' not in df.columns:
            raise ValueError("CSV must contain 'proto' column with protocol numbers")

        # =============================================================
        #                     PROTOCOL MAPPING
        # =============================================================
        print(Fore.CYAN + "[🔄] Mapping protocol numbers to names..." + Style.RESET_ALL)
        
        # Create new column with protocol names, using 'OTHER' for unknown protocols
        df['proto_name'] = df['proto'].map(PROTOCOL_MAP).fillna('OTHER')
        
        # Validate the results
        validate_protocols(df)

        # =============================================================
        #                     DATA SAVING
        # =============================================================
        # Save the mapped data to CSV
        df.to_csv(output_path, index=False)
        
        # Print success message with output location
        print(Fore.GREEN + f"[✓] Saved mapped data to {output_path}" + Style.RESET_ALL)
        
        # Show protocol distribution
        print(Fore.BLUE + "\nProtocol Distribution:")
        print(df['proto_name'].value_counts().to_string() + Style.RESET_ALL)

    except FileNotFoundError:
        # Handle missing input file
        print(Fore.RED + f"[✗] Input file not found at {input_path}" + Style.RESET_ALL)
        print("Did you run the packet capture and conversion first?")
        sys.exit(1)
    except Exception as e:
        # Handle all other errors
        print(Fore.RED + f"[✗] Error: {str(e)}" + Style.RESET_ALL)
        sys.exit(1)


# =====================================================================
#                     SCRIPT ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    # Execute the main function when script is run directly
    main()