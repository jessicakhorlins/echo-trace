# Echotrace

import pyshark
import matplotlib.pyplot as plt
from datetime import datetime

cap = pyshark.FileCapture("sample.pcap")

packet_counts = {}
start_time = None

for packet in cap:
    timestamp = datetime.strptime(packet.sniff_time, "%Y-%m-%d %H:%M:%S.%f")
    if start_time is None:
        start_time = timestamp
    time_diff = (timestamp - start_time).total_seconds() // 60
    if time_diff not in packet_counts:
        packet_counts[time_diff] = 1
    else:
        packet_counts[time_diff] += 1

minutes = list(packet_counts.keys())
packet_numbers = list(packet_counts.values())

plt.plot(minutes, packet_numbers)
plt.xlabel("Time (minutes)")
plt.ylabel("Packet Count")
plt.title("Traffic Patterns Over Time")
plt.show()
