import matplotlib.pyplot as plt
from datetime import datetime
from core.models import NetworkPacket, PCAPFile


def visualize_alert_frequency():
    packets = NetworkPacket.objects.all()

    alert_counts = {}
    timestamps = []

    for packet in packets:
        timestamps.append(
            packet.timestamp
        )

        if detection_function(packet):
            # Group by minute
            time_diff = int((packet.timestamp - timestamps[0]).total_seconds() // 60)
            alert_counts[time_diff] = alert_counts.get(time_diff, 0) + 1

    minutes = list(alert_counts.keys())
    alert_numbers = list(alert_counts.values())

    plt.figure(figsize=(12, 6))
    plt.plot(minutes, alert_numbers, marker="o", linestyle="-")
    plt.xlabel("Time (minutes)")
    plt.ylabel("Alert Count")
    plt.title("Alert Frequency Over Time")
    plt.grid(True)
    plt.show()

def detection_function(packet):
    return (
        packet.is_brute_force
        or packet.is_dos
        or packet.is_sql_injection
        or packet.is_xss
    )
