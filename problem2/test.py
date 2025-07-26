from scapy.all import *
from scapy.layers.ntp import NTP

NTP_UNIX_OFFSET = 2208988800

def packet_callback(pkt):
    # Check for IP, UDP, and NTP layers
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(NTP):
        ip = pkt[IP]
        udp = pkt[UDP]
        ntp = pkt[NTP]
        
        # Filter only NTP packets on port 123
        if udp.dport == 123 or udp.sport == 123:
            print(f"[+] NTP Packet received:")
            print(f" From {ip.src}:{udp.sport} → To {ip.dst}:{udp.dport}")
            print(f" NTP Mode: {ntp.mode}")
            print(f" NTP Version: {ntp.version}")
            
            # Extract covert data from timestamps
            if hasattr(ntp, 'ref') and ntp.ref != 0:
                # Convert float timestamp back to 64-bit integer more carefully
                ref_float = float(ntp.ref)
                ref_seconds = int(ref_float)
                ref_fraction = int(round((ref_float - ref_seconds) * (2**32)))
                ref_timestamp = (ref_seconds << 32) | (ref_fraction & 0xFFFFFFFF)
                
                # Extract hidden bit (bit 8 of fractional part)
                hidden_bit = (ref_timestamp >> 8) & 1
                print(f" Hidden bit from ref timestamp: {hidden_bit}")
                print(f" Ref timestamp: 0x{ref_timestamp:016x}")
            
            if hasattr(ntp, 'orig') and ntp.orig != 0:
                # Convert float timestamp back to 64-bit integer more carefully
                orig_float = float(ntp.orig)
                orig_seconds = int(orig_float)
                orig_fraction = int(round((orig_float - orig_seconds) * (2**32)))
                orig_timestamp = (orig_seconds << 32) | (orig_fraction & 0xFFFFFFFF)
                
                # Extract hidden byte (bits 16-23 of fractional part)
                hidden_byte = (orig_timestamp >> 16) & 0xFF
                hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else f"0x{hidden_byte:02x}"
                print(f" Hidden byte from orig timestamp: {hidden_byte} ('{hidden_char}')")
                print(f" Orig timestamp: 0x{orig_timestamp:016x}")
            
            print("-" * 50)

# Run the sniffer (requires root privileges)
print("[*] Sniffing NTP packets on port 123...")
sniff(filter="udp port 123", prn=packet_callback, store=0)