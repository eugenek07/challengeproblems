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

def build_request(bit, byte_char):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2 ** 32))

    byte_val = ord(byte_char) ^ NTP_PAD_KEY

    # Build NTP packet as raw bytes
    ntp_packet = bytearray(48)

    # NTP header
    ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
    ntp_packet[1] = 0x00
    ntp_packet[2] = 0x06
    ntp_packet[3] = 0xFA

    # Root Delay, Root Dispersion, Reference ID (zeros)
    ntp_packet[4:16] = b'\x00' * 12

    # Reference Timestamp: embed bit in LSB
    ref_fraction = (fraction & 0xFFFFFFFE) | (bit & 0x1)
    ntp_packet[16:24] = struct.pack('>II', seconds, ref_fraction)

    # Originate Timestamp: embed byte in LSB
    orig_fraction = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)
    ntp_packet[24:32] = struct.pack('>II', seconds, orig_fraction)

    # Receive Timestamp (zeros)
    ntp_packet[32:40] = b'\x00' * 8

    # Transmit Timestamp (normal)
    ntp_packet[40:48] = struct.pack('>II', seconds, fraction)

    return Raw(bytes(ntp_packet))


def send_ntp_request(target_ip, bit, byte_char):
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(bit, byte_char)
    send(pkt, verbose=0)
    print(f"[+] Sent byte '{byte_char}' (0x{ord(byte_char):02x}) to {target_ip}")


def sender_loop(ip):
    while True:
        if not message_queue.empty():
            msg = message_queue.get()
            print(f"[*] Sending message: '{msg}'")
            for byte_char in msg:
                send_ntp_request(ip, 1, byte_char)
                time.sleep(1.5)  # allow time to sniff/receive
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
def extract_bit_and_byte(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
    elif packet.haslayer('NTP'):
        try:
            raw_data = bytes(packet[UDP].payload)
        except Exception:
            return None, None
    else:
        return None, None

    if not raw_data or len(raw_data) < 32:
        return None, None

    try:
        _, ref_fraction = struct.unpack(">II", raw_data[16:24])  # Reference
        _, orig_fraction = struct.unpack(">II", raw_data[24:32])  # Originate

        bit = ref_fraction & 0x1
        hidden_byte = (orig_fraction & 0xFF) ^ NTP_PAD_KEY
        return bit, hidden_byte
    except Exception:
        return None, None


def packet_callback(pkt):
    global message
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]
        if (udp.sport == 123 or udp.dport == 123) and ip.src != my_ip:
            bit, hidden_byte = extract_bit_and_byte(pkt)
            if hidden_byte is None:
                return
            try:
                hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                if bit == 1:
                    message += hidden_char
                print(f"Hidden byte: {hidden_byte} ('{hidden_char}') [bit={bit}]")
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
