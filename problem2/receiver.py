from scapy.all import *
import sys
import time
import threading
import queue
import struct

NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue()

def build_request(bit, byte_char):
    # Get current time and convert to NTP format
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    
    # For ref timestamp: modify only the fractional part to embed the bit
    ref_seconds_int = seconds
    ref_fraction_int = (fraction & 0xFFFFFFFE) | (bit & 1)  # Embed bit in LSB of fraction
    
    # For orig timestamp: modify fractional part to embed the byte
    byte_val = ord(byte_char) ^ NTP_PAD_KEY
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

def sender_loop(ip):
    while True:
        if not message_queue.empty():
            msg = message_queue.get()
            print(f"[*] Sending message: '{msg}'")
            for byte_char in msg:
                send_ntp_request(ip, 1, byte_char)
                time.sleep(0.5)  # Small delay to avoid flooding
            print(f"[*] Message complete")

def empty_loop(ip):
    time.sleep(20)
    while True:
        time.sleep(20)
        if message_queue.empty():
            print(f"[*] Sending Blank Packet")
            send_ntp_request(ip, 0, "0")

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
    print(f"[*] Target: {target_ip}")
    print(f"[*] Using raw packet construction to preserve timestamps")
    
    # Start the sender thread
    threading.Thread(target=sender_loop, args=(target_ip,), daemon=True).start()

    threading.Thread(target=empty_loop, args=(target_ip,), daemon=True).start()

    
    # Run the input listener in main thread
    input_listener()