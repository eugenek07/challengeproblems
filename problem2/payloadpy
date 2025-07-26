# sender_receiver.py
from scapy.all import *
from scapy.layers.ntp import NTP
import sys
import time
import threading
import queue

# === SHARED CONSTANTS ===
NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue()


# === SENDER FUNCTIONS ===
def build_request(bit, byte_char):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))

    # Embed 1-bit into fractional part of ref timestamp (LSB of fraction)
    ref_fraction = (fraction & ~1) | (bit & 0x1)
    ref_timestamp = (seconds << 32) | ref_fraction

    # Embed 1-byte (XORed) into fractional part of orig timestamp (LSByte of fraction)
    byte_val = ord(byte_char) ^ NTP_PAD_KEY
    orig_fraction = (fraction & ~0xFF) | (byte_val & 0xFF)
    orig_timestamp = (seconds << 32) | orig_fraction

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
                time.sleep(10)  # Avoid flooding


def input_listener():
    while True:
        try:
            msg = input("Enter message to send: ")
            if msg:
                message_queue.put(msg)
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break


# === RECEIVER FUNCTIONS ===
def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(NTP):
        ip = pkt[IP]
        udp = pkt[UDP]
        ntp = pkt[NTP]

        if udp.sport == 123 or udp.dport == 123:
            print(f"\n[+] NTP Packet from {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")

            # Extract LSB from ref timestamp
            ref = int(ntp.ref)
            hidden_bit = ref & 0x1
            print(f"  ↪ Hidden bit (ref timestamp): {hidden_bit} | Raw: 0x{ref:016x}")

            # Extract hidden byte from orig timestamp
            orig = int(ntp.orig)
            hidden_byte = (orig & 0xFF) ^ NTP_PAD_KEY
            hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
            print(f"  ↪ Hidden byte (orig timestamp): {hidden_byte} ('{hidden_char}') | Raw: 0x{orig:016x}")

            # Extract 2 LSBs from root delay (16.16 fixed-point format)
            root_delay = int(ntp.rootdelay)
            last_two_bits = root_delay & 0b11
            print(f"  ↪ Last 2 bits of root delay: {last_two_bits} | Raw: 0x{root_delay:08x}")

            # Last byte from receive timestamp
            recv_ts = int(ntp.recv)
            recv_byte = recv_ts & 0xFF
            print(f"  ↪ Last byte of receive timestamp: 0x{recv_byte:02x} | Raw: 0x{recv_ts:016x}")

            # Last byte from transmit timestamp
            xmit_ts = int(ntp.sent)
            xmit_byte = xmit_ts & 0xFF
            print(f"  ↪ Last byte of transmit timestamp: 0x{xmit_byte:02x} | Raw: 0x{xmit_ts:016x}")

            print("-" * 60)


# === MAIN ===
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    target_ip = sys.argv[1]

    # Start sender thread
    threading.Thread(target=sender_loop, args=(target_ip,), daemon=True).start()

    # Start packet sniffer in background
    sniff(filter="udp port 123", prn=packet_callback, store=0)
    
    # Listen for user input in main thread
    input_listener()
