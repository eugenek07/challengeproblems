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

def send_ntp_request(target_ip):
    # Use 'F' (0x46) as the last byte of the originate timestamp
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(1, ord('F'))
    send(pkt, verbose=1)
    print(f"NTP request sent to {target_ip}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    ip = sys.argv[1]
    send_ntp_request(ip)
