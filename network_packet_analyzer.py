from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_handler(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        
        if TCP in packet: # TCP details
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print("Payload:")
            print(bytes(packet[TCP].payload))
            print("")

        elif UDP in packet: # UDP details
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print("Payload:")
            print(bytes(packet[UDP].payload))
            print("")
            
        elif ICMP in packet: # ICMP details
            icmp_layer = packet[ICMP]
            print("ICMP Packet")
            print(icmp_layer.summary())
            print("")
        
        else: # Other Protocol details
            print("Other Protocol")
            print("Payload:")
            print(bytes(packet.payload))
            print("")

def start_sniffing(interface):
    try:
        print(f"Starting packet capture on {interface}. Press Ctrl + C to stop capturing Packets")
        sniff(iface=interface, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user")

interface = "Ethernet"  # Specify the network interface (e.g., 'Ethernet')
start_sniffing(interface)
