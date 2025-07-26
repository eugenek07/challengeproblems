<<<<<<< HEAD
# sender.py
from scapy.all import *
from scapy.layers.ntp import NTP
import sys
import time

NTP_UNIX_OFFSET = 2208988800

def build_request():

    ntp_packet = bytearray(48)

    # "00" > LI, "100" > Version, "011" > Mode
    ntp_packet[0] = int("00" + "100" + "011", 2)

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
=======
# INSERT CODE
>>>>>>> c6fdae50fb5bea0b74513cca03c33e0579dc0324
