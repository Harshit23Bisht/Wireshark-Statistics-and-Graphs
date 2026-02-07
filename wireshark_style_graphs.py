from scapy.all import rdpcap, TCP, UDP, DNS
import matplotlib.pyplot as plt
from collections import defaultdict

packets = rdpcap("traffic_statistics.pcapng")   

start_time = int(packets[0].time)

all_packets = defaultdict(int)
tcp_packets = defaultdict(int)
udp_packets = defaultdict(int)
dns_packets = defaultdict(int)
http_packets = defaultdict(int)
tcp_errors = defaultdict(int)

for pkt in packets:

    time_slot = int(pkt.time) - start_time

    all_packets[time_slot] += 1

    if pkt.haslayer(TCP):
        tcp_packets[time_slot] += 1

        if pkt[TCP].sport in [80, 443] or pkt[TCP].dport in [80, 443]:
            http_packets[time_slot] += 1

        if pkt[TCP].flags == "R":
            tcp_errors[time_slot] += 1

    if pkt.haslayer(UDP):
        udp_packets[time_slot] += 1

    if pkt.haslayer(DNS):
        dns_packets[time_slot] += 1


def plot_graph(data, title):

    time = sorted(data.keys())
    values = [data[t] for t in time]

    plt.figure()
    plt.plot(time, values)
    plt.title(title)
    plt.xlabel("Time (seconds)")
    plt.ylabel("Packets per second")
    plt.grid()
    plt.show()

plot_graph(all_packets, "All Packets")
plot_graph(tcp_packets, "TCP Traffic")
plot_graph(udp_packets, "UDP Traffic")
plot_graph(dns_packets, "DNS Traffic")
plot_graph(http_packets, "HTTP/HTTPS Traffic")
plot_graph(tcp_errors, "TCP Errors")
