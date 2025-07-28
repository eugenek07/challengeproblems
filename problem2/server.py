from scapy.all import *
from scapy.layers.ntp import NTP
import time, sys, random, threading, queue, struct

NTP_TIME_OFFSET = 2208988800
NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue()
message = ""

def get_my_ip():
    """Get local IP address more reliably"""
    try:
        # Try to get interface IP
        return get_if_addr(conf.iface)
    except:
        # Fallback method
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            s.close()
            return '127.0.0.1'

my_ip = get_my_ip()

def create_root_delay(msg_on, selector): 
    base_delay = 0x00010200
    base_delay = base_delay & 0xFFFFFFFC
    base_delay = base_delay | (msg_on & 0x1) | ((selector & 0x1) << 1)
    return base_delay

def build_ntp_packet(msg_on, msg_char, selector):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    
    # Build complete NTP packet
    ntp_packet = bytearray(48)
    
    # NTP header
    ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3
    ntp_packet[1] = 0x00  # Stratum
    ntp_packet[2] = 0x06  # Poll
    ntp_packet[3] = 0xFA  # Precision
    
    # Root Delay with embedded msg_on and selector bits
    root_delay = create_root_delay(msg_on, selector)
    ntp_packet[4:8] = struct.pack('>I', root_delay)
    
    # Root Dispersion and Reference ID (zeros)
    ntp_packet[8:16] = b'\x00' * 8
    
    # Reference Timestamp (with bit if needed)
    ref_fraction = fraction | (1 if msg_on else 0)  # embed msg_on bit
    ntp_packet[16:24] = struct.pack('>II', seconds, ref_fraction)
    
    # Originate Timestamp - this is where we embed the message byte
    if msg_on and msg_char:
        if isinstance(msg_char, str):
            byte_val = ord(msg_char) ^ NTP_PAD_KEY
        else:
            byte_val = msg_char ^ NTP_PAD_KEY
        orig_fraction = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)
    else:
        orig_fraction = fraction
    ntp_packet[24:32] = struct.pack('>II', seconds, orig_fraction)
    
    # Receive Timestamp (zeros for client request)
    ntp_packet[32:40] = struct.pack('>II', 0, 0)
    
    # Transmit Timestamp
    ntp_packet[40:48] = struct.pack('>II', seconds, fraction)
    
    return Raw(bytes(ntp_packet))

def send_fake_packets(source, destination, port, msg_on, msg):
    try:
        selector_bit = random.randint(0, 1)
        
        if msg_on and msg:
            msg_char = msg[0] if isinstance(msg, str) and len(msg) > 0 else msg
        else:
            msg_char = None
        
        ntp_packet = build_ntp_packet(msg_on, msg_char, selector_bit)
        
        transport_layer = UDP(sport=port, dport=port)
        network_layer = IP(src=source, dst=destination)
        final_packet = network_layer / transport_layer / ntp_packet
        
        send(final_packet, verbose=0)
        
        if msg_on and msg_char:
            char_display = msg_char if isinstance(msg_char, str) else chr(msg_char)
            print(f"[+] Sent message byte: '{char_display}' (0x{ord(char_display):02x})")
        else:
            print("[+] Sent blank packet")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

def extract_from_raw_payload(packet):
    """Extract the hidden bit and byte from UDP packet"""
    raw_data = None
    
    try:
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
        elif packet.haslayer(UDP):
            # Get raw payload from UDP layer
            udp_layer = packet[UDP]
            if hasattr(udp_layer, 'payload') and udp_layer.payload:
                raw_data = bytes(udp_layer.payload)
    except Exception as e:
        print(f"[!] Error extracting payload: {e}")
        return None, None

    if not raw_data or len(raw_data) < 32:
        return None, None

    try:
        # Extract root delay to check msg_on bit
        root_delay = struct.unpack('>I', raw_data[4:8])[0]
        msg_on = root_delay & 0x1
        
        # Extract from originate timestamp
        _, orig_fraction = struct.unpack('>II', raw_data[24:32])
        hidden_byte_raw = orig_fraction & 0xFF
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY
        
        return msg_on, hidden_byte
    except Exception as e:
        print(f"[!] Error parsing NTP data: {e}")
        return None, None

def packet_callback(pkt):
    global message
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
        return
        
    ip = pkt[IP]
    udp = pkt[UDP]
    
    # Check if it's NTP traffic and not from ourselves
    if not ((udp.sport == 123 or udp.dport == 123) and ip.src != my_ip):
        return
        
    print(f"[*] Received packet from {ip.src}:{udp.sport}")
    
    msg_on, hidden_byte = extract_from_raw_payload(pkt)
    
    if msg_on is None:
        print("[!] Could not extract data from packet")
        return
        
    try:
        if 32 <= hidden_byte <= 126:
            hidden_char = chr(hidden_byte)
        else:
            hidden_char = '.'
            
        if msg_on == 1:  # Only add to message if msg_on bit is set
            message += hidden_char
            print(f"Hidden byte: {hidden_byte} ('{hidden_char}') [msg_on={msg_on}]")
        else:
            print(f"Blank packet received [msg_on={msg_on}]")
    except Exception as e:
        print(f"Decode error: {e}")
        hidden_char = '?'
        
    print("-" * 60)
    
    # ALWAYS send a response
    try:
        if not message_queue.empty():
            next_char = message_queue.get()
            print(f"[*] Sending queued byte back: '{next_char}'")
            send_fake_packets(my_ip, ip.src, 123, True, next_char)
        else:
            print("[*] Sending blank response")
            send_fake_packets(my_ip, ip.src, 123, False, None)
    except Exception as e:
        print(f"[!] Error sending response: {e}")
        
    time.sleep(0.5)

def input_listener():
    while True:
        try:
            msg = input("Enter message to send: ")
            if msg:
                for ch in msg:
                    message_queue.put(ch)
                print(f"[*] Queued message: '{msg}'")
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except EOFError:
            break

def main():
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print(f"[*] My IP: {my_ip}")
    print(f"[*] Target IP: {target_ip}")
    print("[*] Starting sender & receiver threads…")

    # Start input listener thread
    input_thread = threading.Thread(target=input_listener, daemon=True)
    input_thread.start()

    print("[*] Listening for NTP packets on port 123...")
    print("[*] Press Ctrl+C to stop")

    try:
        # Use a more specific filter and handle packets properly
        sniff(filter="udp port 123", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")

    print(f"\n[+] Final Message: '{message}'")

if __name__ == '__main__':
    main()