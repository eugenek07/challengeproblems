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
my_ip = get_if_addr(conf.iface)
message = ''


# === SENDER FUNCTIONS ===
def build_request(bit, byte_char):
    # Get current time and convert to NTP format
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    
    # For ref timestamp: modify only the fractional part to embed the bit
    ref_seconds_int = seconds
    ref_fraction_int = (fraction & 0xFFFFFFFE) | (bit & 1)  # Embed bit in LSB of fraction
    
    # For orig timestamp: modify fractional part to embed the byte
    byte_val = byte_char ^ NTP_PAD_KEY
    orig_seconds_int = seconds
    orig_fraction_int = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)  # Embed byte in lower 8 bits
    
    # Build NTP packet as raw bytes to ensure our timestamps are preserved
    ntp_packet = bytearray(48)
    
    # NTP header
    ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
    ntp_packet[1] = 0x00  # Stratum = 0 (unspecified)
    ntp_packet[2] = 0x06  # Poll = 6
    ntp_packet[3] = 0xFA  # Precision = -6
    
    # Root Delay, Root Dispersion, Reference ID (all zeros)
    ntp_packet[4:16] = b'\x00' * 12
    
    # Reference Timestamp (8 bytes) - with embedded bit
    ntp_packet[16:24] = struct.pack('>II', ref_seconds_int, ref_fraction_int)
    
    # Originate Timestamp (8 bytes) - with embedded byte  
    ntp_packet[24:32] = struct.pack('>II', orig_seconds_int, orig_fraction_int)
    
    # Receive Timestamp (8 bytes) - set to 0 (client request)
    ntp_packet[32:40] = b'\x00' * 8
    
    # Transmit Timestamp (8 bytes) - current time (normal)
    ntp_packet[40:48] = struct.pack('>II', seconds, fraction)
    
    return Raw(bytes(ntp_packet))


def send_ntp_request(target_ip, bit, byte_char):
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(bit, byte_char)
    send(pkt, verbose=0)
    print(f"[+] Sent byte '{byte_char}' (0x{ord(byte_char):02x}) to {target_ip}")
    
    # Debug: show what we embedded
    byte_val = ord(byte_char) ^ NTP_PAD_KEY
    print(f"    Embedded: bit={bit}, byte=0x{byte_val:02x}")

def send_ntp_request_np(target_ip, bit, byte_char):
    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / build_request(bit, byte_char)
    send(pkt, verbose=0)

def sender_loop(ip):
    while True:
        if not message_queue.empty():
            msg = message_queue.get()
            print(f"[*] Sending message: '{msg}'")
            for byte_char in msg:
                send_ntp_request(ip, 1, byte_char)
                time.sleep(10)  # Small delay to avoid flooding
            print(f"[*] Message complete")

def empty_loop(ip):
    time.sleep(10)
    while True:
        time.sleep(10)
        if message_queue.empty():
            send_ntp_request_np(ip, 0, "0")

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
def extract_control_bits_and_byte(packet):
    """Extract control bits from Root Delay and the hidden byte from the chosen timestamp."""
    raw_data = None
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
    elif packet.haslayer('NTP'):
        try:
            udp_layer = packet[UDP]
            raw_data = bytes(udp_layer.payload)
        except Exception:
            pass

    if not raw_data or len(raw_data) < 48:
        return None, None

    try:
        # --- Control Bits from Root Delay ---
        root_delay = struct.unpack(">I", raw_data[4:8])[0]
        has_message = (root_delay >> 31) & 0x1
        use_receive = (root_delay >> 30) & 0x1

        if not has_message:
            return 0, None  # Signal no message

        # --- Select which timestamp to extract from ---
        offset = 32 if use_receive else 40  # Receive or Transmit Timestamp
        _, timestamp_fraction = struct.unpack('>II', raw_data[offset:offset+8])
        hidden_byte_raw = timestamp_fraction & 0xFF
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY  # Unpad the byte

        return 1, hidden_byte
    except Exception:
        return None, None


def packet_callback(pkt, my_ip):
    global message
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]
        if (udp.sport == 123 or udp.dport == 123) and ip.src != my_ip:
            has_msg, hidden_byte = extract_control_bits_and_byte(pkt)
            if has_msg:
                try:
                    hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                    message += hidden_char
                except Exception:
                    hidden_char = '?'
                print(f"Hidden byte: {hidden_byte} ('{hidden_char}')")
                print("-" * 60)
            else:
                # End-of-message signal
                if message:
                    print(f"[+] Final message received: {message}")
                    if not message_queue.empty():
                        next_char = message_queue.get()
                        print(f"[*] Sending queued byte back: '{next_char}'")
                        send_ntp_request(ip.src, 1, next_char)
                        time.sleep(0.5)
                    message = ''

# === MAIN ===
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    print(f"[*] Target: {target_ip}")
    print(f"[*] Using raw packet construction to preserve timestamps")
    
    # Start the sender thread
    threading.Thread(target=sender_loop, args=(target_ip,), daemon=True).start()

    threading.Thread(target=empty_loop, args=(target_ip,), daemon=True).start()

    threading.Thread(target=input_listener, daemon=True).start()
    
    try:
        sniff(filter="udp port 123", prn=lambda pkt: packet_callback(pkt, my_ip), store=0)
    except KeyboardInterrupt:
        print("\n[!] STOP")

    print("\n[+] Final Message:")
    print(message)

