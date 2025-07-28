from scapy.all import *
import sys
import time
import threading
import queue
import struct

# === SHARED CONSTANTS ===
NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue()
my_ip = get_if_addr(conf.iface)
message = ""

def build_request(byte_char):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2 ** 32))

    byte_val = ord(byte_char) ^ NTP_PAD_KEY

    ntp_packet = bytearray(48)

    # NTP header
    ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3
    ntp_packet[1] = 0x00  # Stratum
    ntp_packet[2] = 0x06  # Poll
    ntp_packet[3] = 0xFA  # Precision
    ntp_packet[4:16] = b'\x00' * 12  # Root delay, dispersion, ref ID

    # Reference Timestamp (normal)
    ntp_packet[16:24] = struct.pack(">II", seconds, fraction)
    
    # Originate Timestamp - put byte in the last byte of fraction
    orig_fraction = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)
    ntp_packet[24:32] = struct.pack(">II", seconds, orig_fraction)
    
    # Receive Timestamp (zero)
    ntp_packet[32:40] = struct.pack(">II", 0, 0)
    
    # Transmit Timestamp (normal)
    ntp_packet[40:48] = struct.pack(">II", seconds, fraction)

    return Raw(bytes(ntp_packet))

def send_ntp_request(target_ip, byte_char):
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(byte_char)
    send(pkt, verbose=0)
    print(f"[+] Sent byte '{byte_char}' (0x{ord(byte_char):02x}) to {target_ip}")

def sender_loop(ip):
    while True:
        if not message_queue.empty():
            msg = message_queue.get()
            print(f"[*] Sending message: '{msg}'")
            for byte_char in msg:
                send_ntp_request(ip, byte_char)
                time.sleep(1.5)
            print(f"[*] Message complete")

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
def extract_byte(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
    elif packet.haslayer('NTP'):
        try:
            raw_data = bytes(packet[UDP].payload)
        except Exception:
            return None
    else:
        return None

    if not raw_data or len(raw_data) < 32:
        return None

    try:
        # Extract from Originate Timestamp (bytes 24-31)
        _, orig_fraction = struct.unpack(">II", raw_data[24:32])
        hidden_byte = (orig_fraction & 0xFF) ^ NTP_PAD_KEY
        return hidden_byte
    except Exception:
        return None

def packet_callback(pkt):
    global message
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]
        if (udp.sport == 123 or udp.dport == 123) and ip.src != my_ip:
            hidden_byte = extract_byte(pkt)
            if hidden_byte is None:
                return
            try:
                hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                message += hidden_char
                print(f"Hidden byte: {hidden_byte} ('{hidden_char}')")
            except Exception:
                print("Decode error.")
            print("-" * 60)

# === MAIN ===
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print(f"[*] Target: {target_ip}")
    print("[*] Listening for NTP packets…")

    threading.Thread(target=sender_loop, args=(target_ip,), daemon=True).start()
    threading.Thread(target=input_listener, daemon=True).start()

    try:
        sniff(filter="udp port 123", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")

    print("\n[+] Final Message:")
    print(message)