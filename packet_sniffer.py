from scapy.all import sniff, IP, TCP, UDP, Ether, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse
import time

# Global variables for statistics
packet_count = 0
start_time = time.time()

def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Determine the protocol
        if protocol == 6 and TCP in packet:
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload)
        elif protocol == 17 and UDP in packet:
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload)
        else:
            protocol_name = "Other"
            src_port = dst_port = None
            payload = b""

        # Display packet information
        print(f"\n[+] Packet #{packet_count}")
        print(f"    Source: {ip_src}:{src_port}")
        print(f"    Destination: {ip_dst}:{dst_port}")
        print(f"    Protocol: {protocol_name}")

        # Decode HTTP payload if present
        if payload and TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                try:
                    if HTTPRequest in packet:
                        http_method = packet[HTTPRequest].Method.decode()
                        http_host = packet[HTTPRequest].Host.decode()
                        http_path = packet[HTTPRequest].Path.decode()
                        print(f"    HTTP Request: {http_method} {http_host}{http_path}")
                    elif HTTPResponse in packet:
                        http_status = packet[HTTPResponse].Status_Code.decode()
                        http_reason = packet[HTTPResponse].Reason_Phrase.decode()
                        print(f"    HTTP Response: {http_status} {http_reason}")
                except Exception as e:
                    print(f"    Error decoding HTTP: {e}")

        # Display payload (first 100 bytes)
        if payload:
            print(f"    Payload: {payload[:100]}...")

def display_statistics():
    global packet_count, start_time
    elapsed_time = time.time() - start_time
    print("\n[+] Capture Statistics")
    print(f"    Total Packets Captured: {packet_count}")
    print(f"    Capture Duration: {elapsed_time:.2f} seconds")
    print(f"    Packets per Second: {packet_count / elapsed_time:.2f}")

def start_sniffing(interface=None, filter_rule=None, save_file=None):
    print(f"[+] Starting packet sniffer on interface: {interface or 'default'}")
    print(f"[+] Filter: {filter_rule or 'None'}")
    print(f"[+] Saving to: {save_file or 'None'}")

    try:
        # Start sniffing with optional filter and save file
        sniff(iface=interface, filter=filter_rule, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[+] Stopping packet sniffer...")
        display_statistics()
        if save_file:
            print(f"[+] Saving captured packets to {save_file}...")
            sniff(iface=interface, filter=filter_rule, count=packet_count, offline=save_file)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A realistic packet sniffer tool.")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default=None)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')", default=None)
    parser.add_argument("-o", "--output", help="Save captured packets to a file", default=None)
    args = parser.parse_args()

    # Start the packet sniffer
    start_sniffing(interface=args.interface, filter_rule=args.filter, save_file=args.output)