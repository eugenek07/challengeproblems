from scapy.all import *
import sys
import time
import threading
import queue
import struct

# === SHARED CONSTANTS ===
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

def build_request(byte_char):
    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2 ** 32))

    if isinstance(byte_char, str):
        byte_val = ord(byte_char) ^ NTP_PAD_KEY
    else:
        byte_val = byte_char ^ NTP_PAD_KEY

    ntp_packet = bytearray(48)

    # NTP header
    ntp_packet[0] = 0x23  # LI=0, VN=4, Mode=3
    ntp_packet[1] = 0x00  # Stratum
    ntp_packet[2] = 0x06  # Poll
    ntp_packet[3] = 0xFA  # Precision
    ntp_packet[4:16] = b'\x00' * 12  # Root delay, dispersion, ref ID

    # Reference Timestamp (normal)
    ntp_packet[16:24] = struct.pack(">II", seconds, fraction)
    
    # Originate Timestamp - put byte in the last byte of fraction
    orig_fraction = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)
    ntp_packet[24:32] = struct.pack(">II", seconds, orig_fraction)
    
    # Receive Timestamp (zero)
    ntp_packet[32:40] = struct.pack(">II", 0, 0)
    
    # Transmit Timestamp (normal)
    ntp_packet[40:48] = struct.pack(">II", seconds, fraction)

    return Raw(bytes(ntp_packet))

def send_ntp_request(target_ip, byte_char):
    try:
        # Use a fixed source port for consistency
        sport = random.randint(49152, 65535)  # Use ephemeral port range
        pkt = IP(dst=target_ip) / UDP(sport=sport, dport=123) / build_request(byte_char)
        send(pkt, verbose=0)
        
        char_display = byte_char if isinstance(byte_char, str) else chr(byte_char) if 32 <= byte_char <= 126 else '?'
        print(f"[+] Sent byte '{char_display}' (0x{ord(char_display) if isinstance(char_display, str) else byte_char:02x}) to {target_ip}")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

def sender_loop(ip):
    message_sent = False
    while True:
        try:
            if not message_queue.empty():
                msg = message_queue.get()
                print(f"[*] Sending message: '{msg}'")
                for byte_char in msg:
                    send_ntp_request(ip, byte_char)
                    time.sleep(2)  # Reduced delay
                print(f"[*] Message complete")
                message_sent = True
            elif message_sent:
                # Send blank/dummy packets after message is complete
                send_ntp_request(ip, '\x00')  # or some dummy character
                time.sleep(5)
            else:
                time.sleep(0.1)  # Small delay when waiting for first message
        except Exception as e:
            print(f"[!] Error in sender loop: {e}")
            time.sleep(1)
            
def input_listener():
    while True:
        try:
            msg = input("Enter message to send: ")
            if msg:
                message_queue.put(msg)
                print(f"[*] Queued message: '{msg}'")
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except EOFError:
            break

# === RECEIVER FUNCTIONS ===
def extract_byte(packet):
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
        return None

    if not raw_data or len(raw_data) < 32:
        return None

    try:
        # Extract from Originate Timestamp (bytes 24-31)
        _, orig_fraction = struct.unpack(">II", raw_data[24:32])
        hidden_byte = (orig_fraction & 0xFF) ^ NTP_PAD_KEY
        return hidden_byte
    except Exception as e:
        print(f"[!] Error parsing NTP data: {e}")
        return None

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
    
    hidden_byte = extract_byte(pkt)
    if hidden_byte is None:
        print("[!] Could not extract data from packet")
        return
        
    try:
        if 32 <= hidden_byte <= 126:
            hidden_char = chr(hidden_byte)
        else:
            hidden_char = '.'
        message += hidden_char
        print(f"Hidden byte: {hidden_byte} ('{hidden_char}')")
    except Exception as e:
        print(f"Decode error: {e}")
        
    print("-" * 60)

# === MAIN ===
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print(f"[*] My IP: {my_ip}")
    print(f"[*] Target: {target_ip}")
    print("[*] Starting sender and receiver threads...")

    # Start threads
    sender_thread = threading.Thread(target=sender_loop, args=(target_ip,), daemon=True)
    input_thread = threading.Thread(target=input_listener, daemon=True)
    
    sender_thread.start()
    input_thread.start()

    print("[*] Listening for NTP packets on port 123...")
    print("[*] Press Ctrl+C to stop")

    try:
        sniff(filter="udp port 123", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")

    print(f"\n[+] Final Message: '{message}'")