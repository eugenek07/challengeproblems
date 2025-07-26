from scapy.all import *
from scapy.layers.ntp import NTP
import sys
import time

NTP_UNIX_OFFSET = 2208988800

def build_request(bit, byte):
    # Get current NTP timestamp
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    full_timestamp = (seconds << 32) | fraction

    # Set last bit of reference timestamp
    ref_timestamp = (full_timestamp & ~1) | (bit & 1)

    # Set last byte of originate timestamp
    orig_timestamp = (full_timestamp & ~0xFF) | (byte & 0xFF)

    ntp = NTP()
    ntp.leap = 0
    ntp.version = 4
    ntp.mode = 3

    # Set full 64-bit integer timestamps directly
    ntp.ref = ref_timestamp
    ntp.orig = orig_timestamp

    return ntp

def send_ntp_request(target_ip, byte):
    # Use 'F' (0x46) as the last byte of the originate timestamp
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(1, ord(byte))
    send(pkt, verbose=1)
    print(f"NTP request sent to {target_ip}")

# receiver.py
from scapy.all import *
from scapy.layers.ntp import NTP

def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(NTP):
        ip = pkt[IP]
        udp = pkt[UDP]
        ntp = pkt[NTP]

        if udp.sport == 123 or udp.dport == 123:
            print(f"\n[+] NTP Packet from {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")

            # Extract hidden bit from ref timestamp
            if hasattr(ntp, 'ref'):
                ref = int(ntp.ref)
                hidden_bit = ref & 0x1
                print(f" Hidden bit from ref timestamp: {hidden_bit}")
                print(f" Raw ref timestamp: 0x{ref:016x}")

            # Extract hidden byte from orig timestamp
            if hasattr(ntp, 'orig'):
                orig = int(ntp.orig)
                hidden_byte = orig & 0xFF
                try:
                    hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                except:
                    hidden_char = '?'
                print(f" Hidden byte from orig timestamp: {hidden_byte} ('{hidden_char}')")
                print(f" Raw orig timestamp: 0x{orig:016x}")

            print("-" * 60)
    
    

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP> <Message>")
        sys.exit(1)

    ip = sys.argv[1]
    msg = sys.argv[2]

    for byte in msg:
        send_ntp_request(ip, byte)
    send_ntp_request(ip)
    
    print("[*] Sniffing NTP packets on port 123...")
    sniff(filter="udp port 123", prn=packet_callback, store=0)

    