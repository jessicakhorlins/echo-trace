import pyshark

# Open the pcap file
cap = pyshark.FileCapture("sample.pcap")

# Initialize counters for each category
http_count = 0
dns_count = 0
udp_count = 0
tcp_count = 0
other_count = 0
total_packets = 0

for packet in cap:
    total_packets += 1
    if "http" in packet:
        http_count += 1
    elif "dns" in packet:
        dns_count += 1
    elif "udp" in packet:
        udp_count += 1
    elif "tcp" in packet:
        tcp_count += 1
    else:
        other_count += 1

http_percentage = (http_count / total_packets) * 100
dns_percentage = (dns_count / total_packets) * 100
udp_percentage = (udp_count / total_packets) * 100
tcp_percentage = (tcp_count / total_packets) * 100
other_percentage = (other_count / total_packets) * 100

print(f"HTTP: {http_percentage:.2f}%")
print(f"DNS: {dns_percentage:.2f}%")
print(f"UDP: {udp_percentage:.2f}%")
print(f"TCP: {tcp_percentage:.2f}%")
print(f"Others: {other_percentage:.2f}%")
