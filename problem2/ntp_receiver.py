#!/usr/bin/env python3
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
            print(f"\n[DEBUG] NTP packet from {pkt[IP].src}:")
            
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
        print("\n[!] Stopping receiver...")
