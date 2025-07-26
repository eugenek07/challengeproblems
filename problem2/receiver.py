# sender.py
from scapy.all import *
from scapy.layers.ntp import NTP
import sys
import time

NTP_UNIX_OFFSET = 2208988800

def build_request(bit, byte_char):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    full_timestamp = (seconds << 32) | fraction

    # Embed bit into ref timestamp (LSB)
    ref_timestamp = (full_timestamp & ~1) | (bit & 1)

    # Embed byte into orig timestamp (LSByte)
    byte_val = ord(byte_char)
    orig_timestamp = (full_timestamp & ~0xFF) | (byte_val & 0xFF)

    ntp = NTP()
    ntp.version = 4
    ntp.mode = 3
    ntp.ref = ref_timestamp
    ntp.orig = orig_timestamp

    return ntp

<<<<<<< HEAD
def send_ntp_request(target_ip, bit, char):
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(bit, char)
=======
def send_ntp_request(target_ip, byte):
    # Use 'F' (0x46) as the last byte of the originate timestamp
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(1, ord(byte))
>>>>>>> 1a92acf207c90395cfbdbc21ba6a430fdb9beafb
    send(pkt, verbose=1)
    print(f"[+] NTP request sent to {target_ip} with bit={bit}, byte='{char}'")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP> <Message>")
        sys.exit(1)

<<<<<<< HEAD
    send_ntp_request(sys.argv[1], bit=1, char='F')
=======
    ip = sys.argv[1]
    msg = sys.argv[2]

    for byte in msg:
        send_ntp_request(ip, byte)
    send_ntp_request(ip)
>>>>>>> 1a92acf207c90395cfbdbc21ba6a430fdb9beafb
