from scapy.all import *
from scapy.layers.ntp import NTP
import sys
import time
import threading
import queue

NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue()

def build_request(bit, byte_char):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    full_timestamp = (seconds << 32) | fraction

    # Embed bit into ref timestamp (LSB)
    ref_timestamp = (full_timestamp & ~1) | (bit & 1)

    # Embed byte into orig timestamp (LSByte)
    byte_val = ord(byte_char) ^ NTP_PAD_KEY
    orig_timestamp = (full_timestamp & ~0xFF) | (byte_val & 0xFF)

    ntp = NTP()
    ntp.version = 4
    ntp.mode = 3
    ntp.ref = ref_timestamp
    ntp.orig = orig_timestamp

    return ntp

def send_ntp_request(target_ip, byte):
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(1, byte)
    send(pkt, verbose=0)
    print(f"[+] Sent byte '{byte}' to {target_ip}")

def sender_loop(ip):
    while True:
        if not message_queue.empty():
            msg = message_queue.get()
            for byte in msg:
                send_ntp_request(ip, byte)
                time.sleep(0.5)  # Small delay to avoid flooding

def input_listener():
    while True:
        try:
            msg = input("Enter message to send: ")
            if msg:
                message_queue.put(msg)
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    target_ip = sys.argv[1]

    # Start the sender thread
    threading.Thread(target=sender_loop, args=(target_ip,), daemon=True).start()

    # Run the input listener in main thread
    input_listener()