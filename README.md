📘 README Section
Packet Analyzer GUI – Real-Time Network Packet Capturing and Analysis Tool
This project is a Python-based graphical application for capturing, analyzing, and visualizing network traffic in real-time using the power of Scapy, Tkinter, Pandas, and Matplotlib.

💡 Features
🎯 Live Packet Capture: Captures real-time packets for 10 seconds using Scapy.

🧾 Detailed Packet Inspection: Displays IP, TCP, and UDP layer data including source/destination IPs, ports, sequence numbers, flags, checksums, and more.


📊 Statistical Analysis:
Frequency of Source & Destination IPs

Protocol-wise packet distribution (TCP, UDP)

Bandwidth utilization over time

Traffic trends like packet rate and average packet size


📈 Visualizations:
Bar graph of protocol distribution

Pie charts for IP distribution

Line plots for bandwidth usage and traffic trends


🖥️ User-Friendly GUI:
Built using Tkinter and ttk for a clean, intuitive layout

Scrollable console for live packet logs and analysis summaries

Easy access to all features via dedicated buttons


🔧 Technologies Used
Python 3

Scapy – For packet sniffing and protocol dissection

Tkinter – For building the GUI

Pandas – For traffic data aggregation and transformation

Matplotlib – For visualizing network statistics

Collections.Counter – For frequency counting of IPs and protocols


🧪 How to Run
1.Ensure Python is installed and dependencies are available:
pip install scapy pandas matplotlib

2.Run the script as administrator/root (required for packet sniffing):
sudo python packet_sniffer_gui.py

3.Use the GUI to start capturing packets and exploring network data!

🛡️ Note
This application must be run with administrative privileges due to raw socket access requirements.

The bandwidth utilization is calculated assuming a 1 Mbps total capacity for illustrative purposes, which can be adjusted in the code (total_bandwidth_bps variable).

👨‍💻 Author
K S K KISHORE – Computer Networks Final Project
Developed as part of academic coursework to demonstrate understanding of real-time packet analysis, protocol layers, and bandwidth monitoring.

