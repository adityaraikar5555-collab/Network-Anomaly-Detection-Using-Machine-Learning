from src.flow_extractor import PacketRecord, FlowExtractor


# ---------------------------------------------------------
# CREATE FLOW EXTRACTOR
# ---------------------------------------------------------

extractor = FlowExtractor()


# ---------------------------------------------------------
# FORWARD PACKETS
# ---------------------------------------------------------

packet1 = PacketRecord(
    timestamp=1.0,
    src_ip="192.168.1.113",
    dst_ip="142.251.154.4",
    src_port=14063,
    dst_port=443,
    protocol=6,
    length=1466,
    ip_header_length=20,
    tcp_header_length=20,
    tcp_window_size=65535,
    syn=True,
    ack=True,
    psh=True,
    urg=True,
    cwe=True,
    ece=True,
)

packet2 = PacketRecord(
    timestamp=2.0,
    src_ip="192.168.1.113",
    dst_ip="142.251.154.4",
    src_port=14063,
    dst_port=443,
    protocol=6,
    length=1000,
    ip_header_length=20,
    tcp_header_length=20,
    tcp_window_size=65535,
    ack=True,
    ece=True,
)

packet3 = PacketRecord(
    timestamp=4.0,
    src_ip="192.168.1.113",
    dst_ip="142.251.154.4",
    src_port=14063,
    dst_port=443,
    protocol=6,
    length=1200,
    ip_header_length=20,
    tcp_header_length=20,
    tcp_window_size=65535,
    ack=True,
    psh=True,
)


# ---------------------------------------------------------
# BACKWARD PACKETS
# ---------------------------------------------------------

packet4 = PacketRecord(
    timestamp=5.0,
    src_ip="142.251.154.4",
    dst_ip="192.168.1.113",
    src_port=443,
    dst_port=14063,
    protocol=6,
    length=54,
    ip_header_length=20,
    tcp_header_length=20,
    tcp_window_size=32768,
    ack=True,
    psh=True,
    urg=True,
    cwe=True,
)

packet5 = PacketRecord(
    timestamp=7.0,
    src_ip="142.251.154.4",
    dst_ip="192.168.1.113",
    src_port=443,
    dst_port=14063,
    protocol=6,
    length=60,
    ip_header_length=20,
    tcp_header_length=20,
    tcp_window_size=32768,
    ack=True,
    fin=True,
)


# ---------------------------------------------------------
# ADD PACKETS TO FLOW EXTRACTOR
# ---------------------------------------------------------

extractor.add_packet(packet1)
extractor.add_packet(packet2)
extractor.add_packet(packet3)
extractor.add_packet(packet4)
extractor.add_packet(packet5)


# ---------------------------------------------------------
# GET FLOW
# ---------------------------------------------------------

flows = extractor.get_flows()

print("Number of flows:", len(flows))

flow = flows[0]

print("Total packets:", len(flow.packets))
print("Forward packets:", len(flow.forward_packets))
print("Backward packets:", len(flow.backward_packets))
print("Duration:", flow.duration)


# ---------------------------------------------------------
# CHUNK 1
# FEATURES 1-14
# ---------------------------------------------------------

print("\nCICIDS features:")

features = flow.basic_cicids_features()

for name, value in features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 2
# FEATURES 15-20
# ---------------------------------------------------------

print("\nFlow rate and IAT features:")

rate_iat_features = flow.rate_iat_cicids_features()

for name, value in rate_iat_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 3
# FEATURES 21-30
# ---------------------------------------------------------

print("\nForward and backward IAT features:")

iat_features = flow.forward_backward_iat_features()

for name, value in iat_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 4/5
# FEATURES 31+
# ---------------------------------------------------------

print("\nTCP flag features:")

print(f"Fwd PSH Flags: {flow.fwd_psh_flags}")


# ---------------------------------------------------------
# CHUNK 6
# FEATURES 32-38
# ---------------------------------------------------------

print("\nChunk 6 features:")

chunk6_features = flow.tcp_flag_and_rate_features()

for name, value in chunk6_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 7
# FEATURES 39-49
# ---------------------------------------------------------

print("\nPacket length and TCP flag features:")

chunk7_features = flow.packet_length_and_tcp_flag_features()

for name, value in chunk7_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 8
# FEATURES 50-56
# ---------------------------------------------------------

print("\nChunk 8 features:")

chunk8_features = flow.chunk8_features()

for name, value in chunk8_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 9
# FEATURES 57-62
# ---------------------------------------------------------

print("\nChunk 9 features:")

chunk9_features = flow.chunk9_features()

for name, value in chunk9_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 10
# FEATURES 63-70
# ---------------------------------------------------------

print("\nChunk 10 features:")

chunk10_features = flow.chunk10_features()

for name, value in chunk10_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# CHUNK 11
# FEATURES 71-78
# ---------------------------------------------------------

print("\nChunk 11 features:")

chunk11_features = flow.chunk11_features()

for name, value in chunk11_features.items():
    print(f"{name}: {value}")


# ---------------------------------------------------------
# COMPLETE
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("78-FEATURE PROTOTYPE EXTRACTION COMPLETE")
print("=" * 60)