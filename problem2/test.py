# receiver.py
from scapy.all import *
import struct

# GLOBAL VARIABLES
NTP_PAD_KEY = 0x4A
message = ''

def extract_from_raw_payload(packet):
    """Extract the hidden bit and byte from UDP packet"""
    raw_data = None
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
    elif packet.haslayer('NTP'):
        try:
            udp_layer = packet[UDP]
            raw_data = bytes(udp_layer.payload)
        except Exception:
            pass

    # Error check
    if not raw_data or len(raw_data) < 32:
        return None, None

    try:
        # Unpack reference and originate timestamp fractions
        _, ref_fraction = struct.unpack('>II', raw_data[16:24])
        _, orig_fraction = struct.unpack('>II', raw_data[24:32])

        hidden_bit = ref_fraction & 0x1
        hidden_byte_raw = orig_fraction & 0xFF
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY # UNPAD the hidden byte

        return hidden_bit, hidden_byte
    except Exception:
        return None, None

def packet_callback(pkt):
    global message
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]
        if udp.sport == 123 or udp.dport == 123:
            hidden_bit, hidden_byte = extract_from_raw_payload(pkt)
            if hidden_bit is not None:
                try:
                    hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                    message += hidden_char
                except Exception:
                    hidden_char = '?'
                print(f"Hidden byte: {hidden_byte} ('{hidden_char}')")
            print("-" * 60)

# === MAIN ===
print("[*] Listening for NTP packets on port 123...\n")

try:
    sniff(filter="udp port 123", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\n[!] STOP")

print("\n[+] Final Message:")
print(message)
