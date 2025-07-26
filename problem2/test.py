# receiver.py
from scapy.all import *
from scapy.layers.ntp import NTP

NTP_PAD_KEY = 0x4A

def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(NTP):
        ip = pkt[IP]
        udp = pkt[UDP]
        ntp = pkt[NTP]

        if udp.sport == 123 or udp.dport == 123:
            print(f"\n[+] NTP Packet from {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")

            # Extract hidden bit from ref timestamp
            if hasattr(ntp, 'ref'):
                ref = int(ntp.ref)
                hidden_bit = ref & 0x1
                print(f" Hidden bit from ref timestamp: {hidden_bit}")
                print(f" Raw ref timestamp: 0x{ref:016x}")

            # Extract hidden byte from orig timestamp
            if hasattr(ntp, 'orig'):
                orig = int(ntp.orig)
                hidden_byte = (orig & 0xFF) ^ NTP_PAD_KEY
                try:
                    hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                except:
                    hidden_char = '?'
                print(f" Hidden byte from orig timestamp: {hidden_byte} ('{hidden_char}')")
                print(f" Raw orig timestamp: 0x{orig:016x}")

            print("-" * 60)

print("[*] Sniffing NTP packets on port 123...")
sniff(filter="udp port 123", prn=packet_callback, store=0)
