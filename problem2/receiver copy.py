from scapy.all import *
from scapy.layers.ntp import NTP
import sys
import time

NTP_UNIX_OFFSET = 2208988800

def build_request():

    current_time = time.time()
    seconds = int(current_time) + NTP_UNIX_OFFSET

    fraction = (current_time % 1) * 2**32

    ntp_layer = NTP(
        leap = 0,
        version =4,
        mode = 3,
        transmit_timestamp_secs = seconds,
        transmit_timestamp_frac = fraction,
    )
    return ntp_layer

def send_ntp_request(target_ip):

    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request()
    send(pkt, verbose=1)
    print(f"NTP request sent to {target_ip}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    ip = sys.argv[1]
    send_ntp_request(ip)


'''
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
'''
