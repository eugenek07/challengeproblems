from scapy.all import sniff, TCP, IP

def packet_callback(pkt):
    # Check for IP and TCP layers
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip = pkt[IP]
        tcp = pkt[TCP]

        # Filter only TCP packets on port 8080 (HTTP alternate)
        if tcp.dport == 8080 or tcp.sport == 8080:
            print(f"[+] Packet received:")
            print(f"    From {ip.src}:{tcp.sport} → To {ip.dst}:{tcp.dport}")
            print(f"    Flags: {tcp.flags}")
            print(f"    Seq:   {tcp.seq}")
            print(f"    DataOffset (doff): {tcp.dataofs}")
            print("-" * 40)

# Run the sniffer (requires root privileges)
print("[*] Sniffing TCP packets on port 8080...")
sniff(filter="tcp port 8080", prn=packet_callback, store=0)