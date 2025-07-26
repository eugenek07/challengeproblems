#!/usr/bin/env python3
from scapy.all import *
import struct

# Disable NTP layer parsing to force Raw layer
conf.layers.filter([Ether, IP, UDP, Raw])

NTP_PAD_KEY = 0x4A

def extract_covert_data_from_raw(raw_data):
    """Extract covert data from raw NTP packet bytes"""
    if len(raw_data) < 48:
        return None, None
    
    try:
        # Extract Reference Timestamp (bytes 16-23)
        ref_seconds, ref_fraction = struct.unpack('>II', raw_data[16:24])
        hidden_bit = ref_fraction & 0x1  # Extract LSB
        
        # Extract Originate Timestamp (bytes 24-31)  
        orig_seconds, orig_fraction = struct.unpack('>II', raw_data[24:32])
        hidden_byte_raw = orig_fraction & 0xFF  # Extract lower 8 bits
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY  # Decrypt with pad key
        
        return hidden_bit, hidden_byte
        
    except Exception as e:
        print(f"[-] Error extracting data: {e}")
        return None, None

def packet_callback(pkt):
    """Handle captured packets"""
    if IP in pkt and UDP in pkt and Raw in pkt:
        ip = pkt[IP]
        udp = pkt[UDP]
        raw_data = pkt[Raw].load
        
        # Check if it's an NTP packet (port 123) and has NTP-like structure
        if (udp.sport == 123 or udp.dport == 123) and len(raw_data) >= 48:
            print(f"\n[+] Raw NTP Packet: {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
            print(f"    Payload size: {len(raw_data)} bytes")
            
            # Check if it looks like an NTP packet (first byte should be 0x23 for our packets)
            if len(raw_data) >= 1:
                ntp_header = raw_data[0]
                print(f"    NTP header byte: 0x{ntp_header:02x}")
                
                # Extract covert data
                hidden_bit, hidden_byte = extract_covert_data_from_raw(raw_data)
                
                if hidden_bit is not None and hidden_byte is not None:
                    # Convert byte to character
                    if 32 <= hidden_byte <= 126:  # Printable ASCII
                        hidden_char = chr(hidden_byte)
                        print(f"    ✓ Covert bit: {hidden_bit}")
                        print(f"    ✓ Covert byte: {hidden_byte} → '{hidden_char}'")
                        print(f"    📧 MESSAGE CHAR: '{hidden_char}'")
                    else:
                        print(f"    ✓ Covert bit: {hidden_bit}")
                        print(f"    ✓ Covert byte: {hidden_byte} (0x{hidden_byte:02x})")
                
                # Show timestamp hex for verification
                ref_bytes = raw_data[16:24]
                orig_bytes = raw_data[24:32]
                print(f"    Ref timestamp:  {ref_bytes.hex()}")
                print(f"    Orig timestamp: {orig_bytes.hex()}")
            
            print("-" * 60)

def main():
    print("[*] Simple Raw NTP Covert Channel Receiver")
    print("[*] NTP parsing disabled - treating all UDP port 123 traffic as raw")
    print("[*] Listening for packets...")
    print("[*] Press Ctrl+C to stop")
    print("=" * 60)
    
    try:
        # Sniff for UDP packets on port 123, forcing raw parsing
        sniff(filter="udp port 123", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopping receiver...")

if __name__ == '__main__':
    main()