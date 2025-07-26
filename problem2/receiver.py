from scapy.all import *
import sys
import time
import threading
import queue
import struct

NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue()

def build_raw_ntp_packet(bit, byte_char):
    """Build raw NTP packet with covert data embedded in timestamp bytes"""
    
    # Get current time and convert to NTP timestamp
    current_unix = time.time()
    ntp_time = current_unix + NTP_UNIX_OFFSET
    
    # Create base timestamp (seconds since 1900)
    base_seconds = int(ntp_time)
    base_fraction = int((ntp_time % 1) * (2**32))
    
    # Pack base timestamps as 64-bit values (8 bytes each)
    base_timestamp_bytes = struct.pack('>II', base_seconds, base_fraction)
    
    # Create reference timestamp with embedded bit
    ref_seconds = base_seconds
    ref_fraction = (base_fraction & 0xFFFFFFFE) | (bit & 1)  # Embed bit in LSB
    ref_timestamp_bytes = struct.pack('>II', ref_seconds, ref_fraction)
    
    # Create originate timestamp with embedded byte
    byte_val = ord(byte_char) ^ NTP_PAD_KEY
    orig_seconds = base_seconds
    # Embed byte in the least significant byte of the fraction
    orig_fraction = (base_fraction & 0xFFFFFF00) | (byte_val & 0xFF)
    orig_timestamp_bytes = struct.pack('>II', orig_seconds, orig_fraction)
    
    # Build NTP packet manually (48 bytes total)
    # NTP packet structure:
    # 0: LI(2) + VN(3) + Mode(3) = 1 byte
    # 1: Stratum = 1 byte  
    # 2: Poll = 1 byte
    # 3: Precision = 1 byte
    # 4-7: Root Delay = 4 bytes
    # 8-11: Root Dispersion = 4 bytes
    # 12-15: Reference ID = 4 bytes
    # 16-23: Reference Timestamp = 8 bytes  <-- Our covert bit here
    # 24-31: Originate Timestamp = 8 bytes  <-- Our covert byte here
    # 32-39: Receive Timestamp = 8 bytes
    # 40-47: Transmit Timestamp = 8 bytes
    
    ntp_packet = bytearray(48)
    
    # NTP header
    ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
    ntp_packet[1] = 0x00  # Stratum = 0 (unspecified)
    ntp_packet[2] = 0x06  # Poll = 6
    ntp_packet[3] = 0xFA  # Precision = -6
    
    # Root Delay (4 bytes) - set to 0
    ntp_packet[4:8] = b'\x00\x00\x00\x00'
    
    # Root Dispersion (4 bytes) - set to 0  
    ntp_packet[8:12] = b'\x00\x00\x00\x00'
    
    # Reference ID (4 bytes) - set to 0
    ntp_packet[12:16] = b'\x00\x00\x00\x00'
    
    # Reference Timestamp (8 bytes) - with embedded bit
    ntp_packet[16:24] = ref_timestamp_bytes
    
    # Originate Timestamp (8 bytes) - with embedded byte
    ntp_packet[24:32] = orig_timestamp_bytes
    
    # Receive Timestamp (8 bytes) - set to 0 (client request)
    ntp_packet[32:40] = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    
    # Transmit Timestamp (8 bytes) - current time
    ntp_packet[40:48] = base_timestamp_bytes
    
    return bytes(ntp_packet)

def send_ntp_request(target_ip, byte_char):
    """Send NTP request with embedded covert data"""
    try:
        # Build raw NTP payload
        ntp_payload = build_raw_ntp_packet(1, byte_char)
        
        # Create packet with raw NTP data
        pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=123) / Raw(load=ntp_payload)
        
        send(pkt, verbose=0)
        print(f"[+] Sent byte '{byte_char}' (0x{ord(byte_char):02x}) to {target_ip}")
        
        # Debug: show what we embedded
        byte_val = ord(byte_char) ^ NTP_PAD_KEY
        print(f"    Embedded bit: 1, byte: 0x{byte_val:02x} in timestamps")
        
    except Exception as e:
        print(f"[-] Error sending packet: {e}")

def sender_loop(ip):
    """Main sender loop"""
    while True:
        try:
            if not message_queue.empty():
                msg = message_queue.get()
                print(f"[*] Sending message: '{msg}'")
                for i, byte_char in enumerate(msg):
                    print(f"[*] Sending character {i+1}/{len(msg)}: '{byte_char}'")
                    send_ntp_request(ip, byte_char)
                    time.sleep(0.5)  # Delay between characters
                print(f"[*] Message transmission complete")
            time.sleep(0.1)  # Prevent busy waiting
        except Exception as e:
            print(f"[-] Error in sender loop: {e}")

def input_listener():
    """Listen for user input"""
    print("[*] Raw NTP Covert Channel Sender")
    print("[*] This version directly manipulates NTP packet bytes")
    print("[*] Enter messages to send (Ctrl+C to exit)")
    while True:
        try:
            msg = input("\nEnter message to send: ")
            if msg.strip():
                message_queue.put(msg)
                print(f"[*] Queued message: '{msg}' ({len(msg)} characters)")
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except Exception as e:
            print(f"[-] Input error: {e}")

def create_receiver_script():
    """Generate a companion receiver script"""
    receiver_code = '''#!/usr/bin/env python3
from scapy.all import *
import struct

NTP_PAD_KEY = 0x4A

def extract_covert_data(pkt):
    """Extract covert data from raw NTP packet"""
    if not pkt.haslayer(Raw):
        return None, None
    
    raw_data = pkt[Raw].load
    
    # NTP packet must be exactly 48 bytes
    if len(raw_data) != 48:
        return None, None
    
    try:
        # Extract Reference Timestamp (bytes 16-23)
        ref_timestamp = raw_data[16:24]
        ref_seconds, ref_fraction = struct.unpack('>II', ref_timestamp)
        bit = ref_fraction & 1  # Extract LSB
        
        # Extract Originate Timestamp (bytes 24-31)  
        orig_timestamp = raw_data[24:32]
        orig_seconds, orig_fraction = struct.unpack('>II', orig_timestamp)
        byte_val = orig_fraction & 0xFF  # Extract lower 8 bits
        byte_char = chr(byte_val ^ NTP_PAD_KEY)
        
        return bit, byte_char
        
    except Exception as e:
        print(f"[-] Error extracting data: {e}")
        return None, None

def packet_handler(pkt):
    """Handle captured NTP packets"""
    if pkt.haslayer(UDP) and pkt[UDP].dport == 123 and pkt.haslayer(IP):
        bit, byte_char = extract_covert_data(pkt)
        if bit is not None and byte_char:
            # Check if character is printable
            if 32 <= ord(byte_char) <= 126:  # Printable ASCII
                print(f"[+] From {pkt[IP].src}: bit={bit}, char='{byte_char}' (0x{ord(byte_char):02x})")
            else:
                print(f"[+] From {pkt[IP].src}: bit={bit}, char=<0x{ord(byte_char):02x}>")

def show_packet_analysis(pkt):
    """Show detailed packet analysis for debugging"""
    if pkt.haslayer(Raw) and pkt.haslayer(IP):
        raw_data = pkt[Raw].load
        if len(raw_data) == 48:  # NTP packet
            print(f"\\n[DEBUG] NTP packet from {pkt[IP].src}:")
            
            # Show reference timestamp bytes
            ref_bytes = raw_data[16:24]
            print(f"  Reference timestamp bytes: {ref_bytes.hex()}")
            
            # Show originate timestamp bytes  
            orig_bytes = raw_data[24:32]
            print(f"  Originate timestamp bytes: {orig_bytes.hex()}")
            
            # Extract and show embedded data
            bit, byte_char = extract_covert_data(pkt)
            if bit is not None:
                print(f"  Extracted bit: {bit}")
                print(f"  Extracted char: '{byte_char}' (0x{ord(byte_char):02x})")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='NTP Covert Channel Receiver')
    parser.add_argument('--debug', action='store_true', help='Show detailed packet analysis')
    args = parser.parse_args()
    
    print("[*] Raw NTP Covert Channel Receiver")
    print("[*] Listening for NTP packets on port 123...")
    if args.debug:
        print("[*] Debug mode enabled - showing packet details")
    print("[*] Press Ctrl+C to stop")
    
    try:
        if args.debug:
            sniff(filter="udp port 123", prn=show_packet_analysis, store=0)
        else:
            sniff(filter="udp port 123", prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\\n[!] Stopping receiver...")
'''
    
    with open('ntp_receiver.py', 'w') as f:
        f.write(receiver_code)
    print(f"[*] Receiver script created: ntp_receiver.py")
    print(f"[*] Run with: sudo python3 ntp_receiver.py")
    print(f"[*] Debug mode: sudo python3 ntp_receiver.py --debug")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        print(f"Example: sudo python3 {sys.argv[0]} 8.8.8.8")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    # Create receiver script
    create_receiver_script()
    
    print(f"[*] Target IP: {target_ip}")
    print(f"[*] This version builds raw NTP packets to ensure covert data transmission")
    
    # Start the sender thread
    sender_thread = threading.Thread(target=sender_loop, args=(target_ip,), daemon=True)
    sender_thread.start()
    
    # Run the input listener in main thread
    input_listener()