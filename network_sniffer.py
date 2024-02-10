from scapy.all import sniff
from datetime import datetime

# Define a callback function to handle captured packets
def packet_callback(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto
        length = len(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Length: {length}")

# Start sniffing packets
try:
    print("Starting the network sniffer... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("Stopping the network sniffer.")
