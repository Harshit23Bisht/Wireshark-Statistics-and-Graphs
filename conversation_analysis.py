from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

packets = rdpcap("traffic_statistics.pcapng")

pair_bytes = defaultdict(int)
pair_packets = defaultdict(int)
pair_times = defaultdict(list)
pair_protocols = defaultdict(lambda: defaultdict(int))

for pkt in packets:
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        pair = (src, dst)

        pair_packets[pair] += 1
        pair_bytes[pair] += len(pkt)
        pair_times[pair].append(pkt.time)

        if pkt.haslayer(TCP):
            pair_protocols[pair]["TCP"] += 1
        elif pkt.haslayer(UDP):
            pair_protocols[pair]["UDP"] += 1
        else:
            pair_protocols[pair]["OTHER"] += 1

print("\nUnique Communicating Address Pairs:")
for pair in pair_packets:
    print(pair)

max_pair = max(pair_bytes, key=pair_bytes.get)

print("\nPair Transferring Maximum Bytes:")
print("Pair:", max_pair)
print("Bytes:", pair_bytes[max_pair])

print("\nAverage Inter-Packet Time Difference:")
for pair, times in pair_times.items():
    if len(times) > 1:
        times.sort()
        diffs = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_diff = sum(diffs) / len(diffs)
        print(pair, ":", avg_diff, "seconds")
    else:
        print(pair, ": Only one packet")

print("\nPackets Per Pair and Protocol:")
for pair in pair_protocols:
    print("\nPair:", pair)
    for proto in pair_protocols[pair]:
        print(f"{proto} :", pair_protocols[pair][proto])
