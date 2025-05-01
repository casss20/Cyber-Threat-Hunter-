"""
Cyber Threat Hunter - Enhanced Live Packet Sniffer

Key Improvements:
1. Proper Ctrl+C handling with graceful shutdown
2. Thread-safe packet processing
3. Efficient dashboard updates
4. Reliable packet capture
5. Clean resource cleanup
"""

# =====================================================================
#                           IMPORTS SECTION
# =====================================================================
# Data analysis library for handling structured data
import pandas as pd

# For saving/loading machine learning models
import joblib

# Packet manipulation and network sniffing
from scapy.all import sniff, IP, TCP, UDP, ICMP  # Core networking protocols

# Operating system interfaces
import os  # File/path operations
import sys  # System-specific functions and exit handling

# Time-related functions
import time  # Timestamps and sleep operations

# Threading and synchronization
import threading  # Multi-threading support
import queue  # Thread-safe queue implementation

# Terminal coloring and styling
from colorama import Fore, Style, init  # Cross-platform colored terminal text
init()  # Initialize colorama

# Rich text console and UI components
from rich.console import Console  # Enhanced console output
from rich.table import Table  # For creating formatted tables
from rich.live import Live  # For live-updating displays

# Initialize rich console for pretty printing
console = Console()

# =====================================================================
#                     GLOBAL VARIABLES (THREAD-SAFE)
# =====================================================================
# Threading controls - used to signal when to stop the application
stop_event = threading.Event()

# Queue for thread-safe logging between threads
log_queue = queue.Queue()

# Lock for thread-safe counter updates
counter_lock = threading.Lock()

# Packet counters - track different protocol types
packet_count = 0    # Total packets captured
tcp_count = 0       # TCP protocol packets
udp_count = 0       # UDP protocol packets
icmp_count = 0      # ICMP protocol packets
other_count = 0     # Other/unknown protocol packets

# =====================================================================
#                     MODEL LOADING SECTION
# =====================================================================
def load_model():
    """Load trained ML model with comprehensive error handling
    
    Returns:
        The loaded machine learning model
        
    Exits:
        If model file not found or loading fails
    """
    try:
        # Get the project base directory (two levels up from current file)
        base_dir = os.path.dirname(os.path.dirname(__file__))
        model_path = os.path.join(base_dir, 'outputs', 'random_forest_model.pkl')
        
        # Verify model exists before attempting to load
        if not os.path.exists(model_path):
            console.print("\n[bold red]⚠️ Model not found! Train the model first.[/bold red]")
            sys.exit(1)
            
        return joblib.load(model_path)
    except Exception as e:
        console.print(f"\n[bold red]⚠️ Model loading error: {e}[/bold red]")
        sys.exit(1)

# Load the model at startup
model = load_model()

# =====================================================================
#                     PACKET PROCESSING LOGIC
# =====================================================================
def process_packet(packet):
    """
    Thread-safe packet processing with:
    - Layer detection
    - Model fallback
    - Efficient logging
    
    Args:
        packet: The network packet captured by scapy
    """
    global packet_count, tcp_count, udp_count, icmp_count, other_count
    
    # Skip non-IP packets
    if not packet.haslayer(IP):
        return

    protocol = None
    ip_layer = packet[IP]
    
    # Thread-safe counter updates using context manager
    with counter_lock:
        packet_count += 1
        
        # Protocol detection hierarchy
        if packet.haslayer(TCP):
            tcp_count += 1
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            udp_count += 1
            protocol = 'UDP'
        elif packet.haslayer(ICMP):
            icmp_count += 1
            protocol = 'ICMP'
        else:
            # Fallback to model prediction if layer detection fails
            try:
                protocol = model.predict(pd.DataFrame({'proto': [ip_layer.proto]}))[0]
                if protocol == 'TCP':
                    tcp_count += 1
                elif protocol == 'UDP':
                    udp_count += 1
                elif protocol == 'ICMP':
                    icmp_count += 1
                else:
                    other_count += 1
            except Exception as e:
                console.print(f"[bold yellow]⚠️ Prediction error: {e}[/bold yellow]")
                return

    # Queue packets for background logging (only TCP/UDP)
    if protocol in ['TCP', 'UDP']:
        log_entry = {
            'timestamp': time.time(),
            'protocol': protocol,
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'sport': packet.sport if hasattr(packet, 'sport') else None,
            'dport': packet.dport if hasattr(packet, 'dport') else None
        }
        log_queue.put(log_entry)

# =====================================================================
#                     BACKGROUND SERVICES
# =====================================================================
def log_writer():
    """Dedicated thread for efficient log writing
    
    Continuously writes packet logs to file in batches
    until stop_event is triggered
    """
    log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                          'outputs', 'suspicious_packets_log.txt')
    
    while not stop_event.is_set():
        try:
            with open(log_path, 'a') as f:
                # Batch write up to 10 entries at once for efficiency
                for _ in range(10):
                    entry = log_queue.get_nowait()
                    f.write(
                        f"{entry['timestamp']},"
                        f"{entry['protocol']},"
                        f"{entry['src']}:{entry['sport']},"
                        f"{entry['dst']}:{entry['dport']}\n"
                    )
        except queue.Empty:
            # No entries in queue, brief sleep to prevent CPU spin
            time.sleep(0.1)
        except Exception as e:
            console.print(f"[bold red]⚠️ Log write error: {e}[/bold red]")
            time.sleep(1)

def dashboard_controller():
    """Manage dashboard updates with controlled refresh rate
    
    Uses rich.Live for smooth terminal dashboard updates
    """
    with Live(generate_dashboard(), refresh_per_second=4, console=console) as live:
        while not stop_event.is_set():
            live.update(generate_dashboard())
            time.sleep(0.25)  # 4 updates per second

# =====================================================================
#                     USER INTERFACE COMPONENTS
# =====================================================================
def generate_dashboard():
    """Create the Rich dashboard table with current statistics
    
    Returns:
        A rich.Table object with current packet counts
    """
    table = Table(title="🚀 CyberHunter Live Dashboard", title_style="bold cyan")
    table.add_column("Metric", justify="left", style="bold yellow")
    table.add_column("Count", justify="right", style="bold green")
    
    with counter_lock:  # Thread-safe counter access
        table.add_row("Total Packets", str(packet_count))
        table.add_row("TCP Packets", str(tcp_count))
        table.add_row("UDP Packets", str(udp_count))
        table.add_row("ICMP Packets", str(icmp_count))
        table.add_row("Other Protocols", str(other_count))
    
    return table

# =====================================================================
#                     MAIN CAPTURE FUNCTION
# =====================================================================
def run_capture(filter_exp='all'):
    """
    Start packet capture with comprehensive management
    
    Args:
        filter_exp: BPF filter expression for packet capture
        
    Features:
    - Dedicated sniffer thread
    - Background services
    - Clean shutdown handling
    """
    # Start background services as daemon threads
    threading.Thread(target=log_writer, daemon=True).start()
    threading.Thread(target=dashboard_controller, daemon=True).start()
    
    try:
        console.print("\n[bold green]✅ Starting packet capture... (Ctrl+C to stop)[/bold green]")
        
        # Start packet sniffing with options:
        sniff(
            prn=process_packet,      # Callback for each packet
            store=False,             # Don't store packets in memory
            filter=None if filter_exp == 'all' else filter_exp,
            stop_filter=lambda _: stop_event.is_set()  # Stop condition
        )
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]🛑 Stopping capture...[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]⚠️ Capture error: {e}[/bold red]")
    finally:
        # Clean shutdown sequence
        stop_event.set()
        time.sleep(0.5)  # Allow threads to finish
        console.print(generate_dashboard())
        console.print(f"\n[bold green]📊 Final count: {packet_count} packets[/bold green]")

# =====================================================================
#                     MAIN PROGRAM
# =====================================================================
if __name__ == "__main__":
    try:
        console.print("[bold cyan]🚀 CyberHunter Packet Sniffer[/bold cyan]")
        run_capture()
    except Exception as e:
        console.print(f"\n[bold red]⚠️ Fatal error: {e}[/bold red]")
    finally:
        stop_event.set()
        console.print("\n[bold blue]👋 Exiting CyberHunter[/bold blue]")