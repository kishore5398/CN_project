import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk  # For themed widgets
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
from scapy.all import sniff
import time

captured_packets = []
bandwidth_utilization_percentage = []
total_bandwidth_bps = 1 * 1_000_000
capture_duration = 10  
interval_duration = 2

def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        packet_info = f"\n================= New Packet =================\n"
        packet_info += f"** IP Layer **\n"
        packet_info += f"  Source IP          : {ip_layer.src}\n"
        packet_info += f"  Destination IP     : {ip_layer.dst}\n"
        packet_info += f"  Protocol           : {ip_layer.proto}\n"
        packet_info += f"  Length             : {ip_layer.len}\n"
        packet_info += f"  Checksum           : {ip_layer.chksum}\n"
        packet_info += f"  Timestamp          : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}\n"

        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            packet_info += f"** TCP Layer **\n"
            packet_info += f"  Source Port        : {tcp_layer.sport}\n"
            packet_info += f"  Destination Port   : {tcp_layer.dport}\n"
            packet_info += f"  Sequence Number    : {tcp_layer.seq}\n"
            packet_info += f"  Acknowledgment No. : {tcp_layer.ack}\n"
            packet_info += f"  Flags              : {tcp_layer.flags}\n"
            packet_info += f"  Window Size        : {tcp_layer.window}\n"
            packet_info += f"  Checksum           : {tcp_layer.chksum}\n"
            packet_info += f"  Urgent Pointer     : {tcp_layer.urgptr}\n"

        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            packet_info += f"** UDP Layer **\n"
            packet_info += f"  Source Port        : {udp_layer.sport}\n"
            packet_info += f"  Destination Port   : {udp_layer.dport}\n"
            packet_info += f"  Length             : {udp_layer.len}\n"
            packet_info += f"  Checksum           : {udp_layer.chksum}\n"

        captured_packets.append({
            'Source IP': ip_layer.src,
            'Destination IP': ip_layer.dst,
            'Protocol': ip_layer.proto,
            'Length': ip_layer.len,
            'Checksum': ip_layer.chksum,
            'Timestamp': packet.time
        })
        text_area.insert(tk.END, packet_info)
        text_area.see(tk.END)

def start_packet_capture():
    text_area.insert(tk.END, "Starting packet capture for 10 seconds...\n")
    sniff(prn=packet_callback, timeout=10)
    text_area.insert(tk.END, "Packet capture completed.\n")

def show_packet_data():
    df = pd.DataFrame(captured_packets)
    text_area.insert(tk.END, f"\nCaptured Packet Data:\n{df}\n")

def show_source_ip_frequency():
    src_ips = [packet['Source IP'] for packet in captured_packets if 'Source IP' in packet]
    src_ip_count = Counter(src_ips)
    text_area.insert(tk.END, "\n--- Source IP Frequency ---\n")
    for ip, count in src_ip_count.items():
        text_area.insert(tk.END, f"{ip}: {count} packets\n")

def show_destination_ip_frequency():
    dst_ips = [packet['Destination IP'] for packet in captured_packets if 'Destination IP' in packet]
    dst_ip_count = Counter(dst_ips)
    text_area.insert(tk.END, "\n--- Destination IP Frequency ---\n")
    for ip, count in dst_ip_count.items():
        text_area.insert(tk.END, f"{ip}: {count} packets\n")

def show_protocol_frequency():
    protocols = [packet.get('Protocol') for packet in captured_packets if 'Protocol' in packet]
    protocol_count = Counter(protocols)
    text_area.insert(tk.END, "\n--- Protocol Frequency ---\n")
    for protocol, count in protocol_count.items():
        text_area.insert(tk.END, f"{protocol}: {count} packets\n")

def show_protocol_distribution():
    protocols = [packet.get('Protocol') for packet in captured_packets if 'Protocol' in packet]
    protocol_count = Counter(protocols)

    plt.figure(figsize=(10, 5))
    plt.bar(protocol_count.keys(), protocol_count.values(), color='skyblue')
    plt.title('Protocol Distribution (TCP vs UDP)')
    plt.xlabel('Protocol')
    plt.ylabel('Number of Packets')
    plt.show()

def show_ip_distribution():
    src_ips = [packet['Source IP'] for packet in captured_packets if 'Source IP' in packet]
    dst_ips = [packet['Destination IP'] for packet in captured_packets if 'Destination IP' in packet]

    src_ip_count = Counter(src_ips)
    dst_ip_count = Counter(dst_ips)

    plt.figure(figsize=(8, 8))
    plt.pie(src_ip_count.values(), labels=src_ip_count.keys(), autopct='%1.1f%%', startangle=140)
    plt.title('Source IP Distribution')
    plt.show()

    plt.figure(figsize=(8, 8))
    plt.pie(dst_ip_count.values(), labels=dst_ip_count.keys(), autopct='%1.1f%%', startangle=140)
    plt.title('Destination IP Distribution')
    plt.show()

def show_bandwidth_utilization():
    df = pd.DataFrame(captured_packets)
    total_data_transferred = df['Length'].sum()

    start_time = df['Timestamp'].iloc[0]
    end_time = df['Timestamp'].iloc[-1]
    time_period = end_time - start_time

    bandwidth_utilization_bps = (total_data_transferred * 8) / time_period if time_period > 0 else 0
    utilization_percentage = (bandwidth_utilization_bps / total_bandwidth_bps) * 100 if total_bandwidth_bps > 0 else 0

    text_area.insert(tk.END, f"\nTotal Data Transferred: {total_data_transferred} bytes\n")
    text_area.insert(tk.END, f"Time Period: {time_period} seconds\n")
    text_area.insert(tk.END, f"Bandwidth Utilization: {bandwidth_utilization_bps:.2f} bps\n")
    text_area.insert(tk.END, f"Total Available Bandwidth: {total_bandwidth_bps / 1_000_000:.2f} Mbps\n")
    text_area.insert(tk.END, f"Utilization Percentage: {utilization_percentage:.2f}%\n")

    bandwidth_utilization_percentage.clear()
    for i in range(len(captured_packets)):
        if i == 0:
            time_window_start = captured_packets[i]['Timestamp']
        time_window_end = captured_packets[i]['Timestamp']
        total_data_transferred_window = sum(packet['Length'] for packet in captured_packets[:i + 1])
        
        time_period_window = time_window_end - time_window_start
        bandwidth_utilization_bps_window = (total_data_transferred_window * 8) / time_period_window if time_period_window > 0 else 0
        utilization_percentage_window = (bandwidth_utilization_bps_window / total_bandwidth_bps) * 100 if total_bandwidth_bps > 0 else 0
        
        bandwidth_utilization_percentage.append(utilization_percentage_window)

    plt.figure(figsize=(12, 6))
    plt.plot(bandwidth_utilization_percentage, marker='o', color='orange')
    plt.title('Bandwidth Utilization Percentage Over Time')
    plt.xlabel('Packet Number')
    plt.ylabel('Utilization Percentage (%)')
    plt.ylim(0, 100)
    plt.grid()
    plt.axhline(y=100, color='r', linestyle='--', label='100% Utilization')
    plt.legend()
    plt.show()

def show_traffic_trends():
    if not captured_packets:
        text_area.insert(tk.END, "No packets captured yet. Please start packet capture first.\n")
        return
    
    df = pd.DataFrame(captured_packets)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')  
    df['Elapsed Time'] = (df['Timestamp'] - df['Timestamp'].iloc[0]).dt.total_seconds()
    df.set_index('Timestamp', inplace=True)

    interval_data = df.resample(f'{interval_duration}s').agg({
        'Length': ['count', 'mean'],  
        'Source IP': lambda x: Counter(x).most_common(1)[0][0] if x.any() else None,
        'Destination IP': lambda x: Counter(x).most_common(1)[0][0] if x.any() else None  
    })

    interval_data.columns = ['Packet Count', 'Avg Packet Size', 'Most Common Source IP', 'Most Common Dest IP']

    text_area.insert(tk.END, f"\nTraffic Summary (Grouped by Interval):\n{interval_data}\n")
    
    elapsed_time_seconds = (interval_data.index - interval_data.index[0]).total_seconds()

    plt.figure(figsize=(12, 6))
    plt.subplot(2, 1, 1)
    plt.plot(elapsed_time_seconds, interval_data['Packet Count'], marker='o', color='b', label='Packet Count')
    plt.title('Traffic Trends Over Capture Duration')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Count')
    plt.legend()
    plt.grid()

    plt.subplot(2, 1, 2)
    plt.plot(elapsed_time_seconds, interval_data['Avg Packet Size'], marker='o', color='g', label='Avg Packet Size (bytes)')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Average Packet Size (bytes)')
    plt.legend()
    plt.grid()

    plt.tight_layout()
    plt.show()

app = tk.Tk()
app.title("Packet Capture GUI")

# Adding some styling to the GUI
style = ttk.Style()
style.configure("TButton", font=("Helvetica", 12), padding=10, background="lightblue", foreground="black")
style.configure("TLabel", font=("Helvetica", 12), padding=10)
style.configure("TFrame", background="lightgrey")

main_frame = ttk.Frame(app, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

# Function to create and place buttons in a grid
def create_button(frame, text, command, row, col):
    button = ttk.Button(frame, text=text, command=command)
    button.grid(row=row, column=col, padx=5, pady=5, sticky='nsew')
    return button

buttons = [
    ("Start Capturing Packets", start_packet_capture),
    ("Show Packet Data", show_packet_data),
    ("Show Source IP Frequency", show_source_ip_frequency),
    ("Show Destination IP Frequency", show_destination_ip_frequency),
    ("Show Protocol Frequency", show_protocol_frequency),
    ("Show Protocol Distribution", show_protocol_distribution),
    ("Show IP Distribution", show_ip_distribution),
    ("Show Bandwidth Utilization", show_bandwidth_utilization),
    ("Show Traffic Trends", show_traffic_trends)
]

for i, (text, command) in enumerate(buttons):
    create_button(main_frame, text, command, i // 3, i % 3)

# Configure grid to make sure buttons occupy the entire row
for i in range(3):
    main_frame.columnconfigure(i, weight=1)

text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=20, font=("Helvetica", 12))
text_area.grid(row=len(buttons) // 3, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')

app.mainloop()
