# receiver.py
from scapy.all import *
import struct

NTP_PAD_KEY = 0x4A

def extract_from_raw_payload(pkt):
    """Extract covert data from raw UDP payload"""
    raw_data = None
    
    # Try multiple ways to get the UDP payload
    if pkt.haslayer(Raw):
        raw_data = pkt[Raw].load
    elif pkt.haslayer('NTP'):
        # If Scapy parsed it as NTP, get the original bytes
        try:
            # Reconstruct the packet bytes
            udp_layer = pkt[UDP]
            raw_data = bytes(udp_layer.payload)
        except:
            pass
    
    if not raw_data or len(raw_data) < 48:
        return None, None
    
    try:
        # Extract Reference Timestamp (bytes 16-23)
        ref_seconds, ref_fraction = struct.unpack('>II', raw_data[16:24])
        hidden_bit = ref_fraction & 0x1
        
        # Extract Originate Timestamp (bytes 24-31)
        orig_seconds, orig_fraction = struct.unpack('>II', raw_data[24:32])
        hidden_byte_raw = orig_fraction & 0xFF
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY
        
        return hidden_bit, hidden_byte
    except Exception as e:
        print(f"   Debug: extraction error - {e}")
        return None, None

def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]
        
        if udp.sport == 123 or udp.dport == 123:
            print(f"\n[+] NTP Packet from {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
            
            # Debug: show what layers we have
            layers = [layer.name for layer in pkt.layers()]
            print(f"   Layers: {layers}")
            
            # Try to extract from raw payload (works for both Raw and NTP layers)
            hidden_bit, hidden_byte = extract_from_raw_payload(pkt)
            
            if hidden_bit is not None and hidden_byte is not None:
                try:
                    hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                except:
                    hidden_char = '?'
                
                print(f" ✓ Hidden bit: {hidden_bit}")
                print(f" ✓ Hidden byte: {hidden_byte} ('{hidden_char}')")
                print(f" ✓ MESSAGE CHAR: '{hidden_char}'")
            else:
                print(f"   ❌ Could not extract covert data")
            
            # Show raw timestamp bytes for debugging
            raw_data = None
            if pkt.haslayer(Raw):
                raw_data = pkt[Raw].load
            elif pkt.haslayer('NTP'):
                try:
                    raw_data = bytes(pkt[UDP].payload)
                except:
                    pass
            
            if raw_data and len(raw_data) >= 32:
                ref_bytes = raw_data[16:24]
                orig_bytes = raw_data[24:32]
                print(f"   Ref timestamp bytes:  {ref_bytes.hex()}")
                print(f"   Orig timestamp bytes: {orig_bytes.hex()}")
                
                # Show the actual embedded values
                try:
                    ref_seconds, ref_fraction = struct.unpack('>II', ref_bytes)
                    orig_seconds, orig_fraction = struct.unpack('>II', orig_bytes)
                    print(f"   Ref fraction: 0x{ref_fraction:08x} (LSB: {ref_fraction & 1})")
                    print(f"   Orig fraction: 0x{orig_fraction:08x} (Lower byte: 0x{orig_fraction & 0xFF:02x})")
                except:
                    pass
            
            print("-" * 60)

print("[*] Hybrid NTP Receiver - handles both raw and NTP layer packets")
print("[*] Sniffing NTP packets on port 123...")
sniff(filter="udp port 123", prn=packet_callback, store=0)