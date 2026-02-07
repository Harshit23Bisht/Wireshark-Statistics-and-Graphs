from scapy.all import rdpcap

packets = rdpcap("traffic_statistics.pcapng")  

total_packets = 0
total_packet_size = 0
total_payload_size = 0

for pkt in packets:
    total_packets += 1
    total_packet_size += len(pkt)

    # payload size
    if pkt.payload:
        total_payload_size += len(pkt.payload)

header_size = total_packet_size - total_payload_size

print("Total Packets :", total_packets)
print("Total Packet Size :", total_packet_size, "bytes")
print("Total Payload Size :", total_payload_size, "bytes")
print("Total Header Size :", header_size, "bytes")
