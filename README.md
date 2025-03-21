# PRODIGY_CS_05
A realistic and functional packet sniffer built in Python using the scapy library. This tool captures and analyzes network traffic, displaying detailed information such as source and destination IP addresses, protocols, and payload data. It is designed for educational purposes to help users understand network protocols and packet structures.

Features
Packet Capture: Captures live network traffic on a specified interface.

Protocol Decoding: Supports TCP, UDP, and HTTP protocols.

Filtering: Allows users to filter packets using Berkeley Packet Filter (BPF) rules (e.g., tcp port 80).

Payload Analysis: Decodes and displays HTTP requests and responses.

Statistics: Provides real-time statistics like packet count, capture duration, and packets per second.

Save Captures: Saves captured packets to a .pcap file for later analysis.

Real-Time Display: Displays packets in a clean, organized format as they are captured.


How It Works
The tool uses the scapy library to capture and decode network packets. It analyzes packet headers and payloads, extracting relevant information such as:

Source and destination IP addresses.

Source and destination ports.

Protocol type (TCP, UDP, etc.).

Payload data (e.g., HTTP requests/responses).


Ethical Use
This tool is intended for educational purposes only. Always ensure you have proper authorization before capturing or analyzing network traffic. Do not use this tool to capture sensitive or private data.


Contributing
Contributions are welcome! If you'd like to add features, improve the code, or report issues, please open an issue or submit a pull request.

Author
Dilip Bindra
Email: rohitbindra1920@gmail.com
