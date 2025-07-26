# receiver.py
from scapy.all import *
import struct

# === GLOBAL VARIABLES ===
NTP_PAD_KEY = 0x4A
message = ''

def extract_from_raw_payload(packet):
    """Extract covert data from raw UDP payload"""
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
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY

        return hidden_bit, hidden_byte
    except Exception:
        return None, None

def packet_callback(pkt):
    global message  # Fix for modifying the global message

    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]

        if udp.sport == 123 or udp.dport == 123:
            print(f"\n[+] NTP Packet from {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")

            hidden_bit, hidden_byte = extract_from_raw_payload(pkt)

            if hidden_bit is not None and hidden_byte is not None:
                try:
                    hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                    message += hidden_char
                except Exception:
                    hidden_char = '?'
                print(f" ✓ Hidden byte: {hidden_byte} ('{hidden_char}')")

            # Debug timestamp bytes
            try:
                raw_data = bytes(pkt[UDP].payload)
                if len(raw_data) >= 32:
                    ref_bytes = raw_data[16:24]
                    orig_bytes = raw_data[24:32]

                    ref_seconds, ref_fraction = struct.unpack('>II', ref_bytes)
                    orig_seconds, orig_fraction = struct.unpack('>II', orig_bytes)

                    print(f"   Ref timestamp bytes:  {ref_bytes.hex()}")
                    print(f"   Orig timestamp bytes: {orig_bytes.hex()}")
                    print(f"   Ref fraction: 0x{ref_fraction:08x} (LSB: {ref_fraction & 1})")
                    print(f"   Orig fraction: 0x{orig_fraction:08x} (Lower byte: 0x{orig_fraction & 0xFF:02x})")
            except Exception:
                pass

            print("-" * 60)

# === MAIN ===
print("[*] Hybrid NTP Receiver - handles both raw and NTP layer packets")
print("[*] Sniffing NTP packets on port 123... (Press Ctrl+C to stop)\n")

try:
    sniff(filter="udp port 123", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\n[!] Sniffing stopped.")

print("\n[+] Final Reconstructed Message:")
print(message)
