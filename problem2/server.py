from scapy.all import *
from scapy.layers.ntp import NTP
import time, sys, random, threading, queue, struct

NTP_TIME_OFFSET = 2208988800
NTP_PAD_KEY = 0x4A
NTP_UNIX_OFFSET = 2208988800
message_queue = queue.Queue() # this queue contains each message that we will be sending byte-by-byte
message = "" # this is the final message that the other person has sent me
my_ip = get_if_addr(conf.iface)

def create_root_delay(msg_on, selector): 
    base_delay = 0x00010200  # believable root delay
    
    # Clear last two bits (bits 0 and 1)
    base_delay = base_delay & 0xFFFFFFFC
    
    # Set bit 0 to msg_on, bit 1 to selector
    base_delay = base_delay | (msg_on & 0x1) | ((selector & 0x1) << 1)
    
    return base_delay

def embed_msg_in_ts(timestamp, msg, msg_on, selector):
    '''
        args: 
            - timestamp: the timestamp we are embedding a message within
            - msg: the message we are embedding
        return: Timestamp where last byte is the message
        This function takes a timestamp and embeds the message in the last byte of the timestamp
    '''
    
    # # first, zero-out the last byte (2 hex digits) of the timestamp
    # #   0x FF FF FF FF FF FF FF 00
    # # & __ __ __ __ __ __ __ __ 00 
    # # = __ __ __ __ __ __ __ __ 00
    # timestamp = timestamp & 0xFFFFFFFFFFFFFF00

    # # second, OR the result with the message to set the last byte
    # #   0x FF FF FF FF FF FF FF 00
    # # | __ __ __ __ __ __ __ __ msg 
    # # = __ __ __ __ __ __ __ __ msg
    # timestamp = timestamp | (msg ^ NTP_PAD_KEY)

    current_time = time.time() + NTP_UNIX_OFFSET
    seconds = int(current_time)
    fraction = int((current_time % 1) * (2**32))
    
    # Prepare timestamps
    ref_seconds_int = seconds
    ref_fraction_int = fraction  # or could embed bit if needed
    
    orig_seconds_int = seconds
    orig_fraction_int = fraction  # keep originate timestamp normal
    
    recv_seconds_int = seconds
    trans_seconds_int = seconds
    
    byte_val = ord(msg) ^ NTP_PAD_KEY

    if selector == 1:
        # Embed in Receive Timestamp
        recv_fraction_int = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)
        trans_fraction_int = fraction  # normal
    else:
        # Embed in Transmit Timestamp
        recv_fraction_int = fraction  # normal
        trans_fraction_int = (fraction & 0xFFFFFF00) | (byte_val & 0xFF)
    
    # Build NTP packet as raw bytes to ensure our timestamps are preserved
    ntp_packet = bytearray(48)
    
    # NTP header
    ntp_packet[0] = 0x24  # LI=0, VN=4, Mode=4 (server)
    ntp_packet[1] = 0x00  # Stratum = 0 (unspecified)
    ntp_packet[2] = 0x06  # Poll = 6
    ntp_packet[3] = 0xFA  # Precision = -6
    
    # Root Delay, Root Dispersion, Reference ID (all zeros)
    ntp_packet[4:8] = struct.pack('>I', create_root_delay(msg_on, selector))
    
    # Reference Timestamp (8 bytes) - with embedded bit
    ntp_packet[16:24] = struct.pack('>II', ref_seconds_int, ref_fraction_int)
    
    # Originate Timestamp (8 bytes) - with embedded byte  
    ntp_packet[24:32] = struct.pack('>II', orig_seconds_int, orig_fraction_int)
    
    # Receive Timestamp (may have embedded byte)
    ntp_packet[32:40] = struct.pack('>II', recv_seconds_int, recv_fraction_int)
    
    # Transmit Timestamp (may have embedded byte)
    ntp_packet[40:48] = struct.pack('>II', trans_seconds_int, trans_fraction_int)

    return Raw(bytes(ntp_packet))

def send_fake_packets(source, destination, port, msg_on, msg):
    '''
        args: 
            - source: source IP
            - destination: destination IP
            - port: port number
            - msg_on: whether a message is actually being sent in the covert channel
            - msg: the message, if msg_on = True
        returns: N/A
        This function generates fake NTP packets with a selector that tells us which of three timestamps (reference,
        originate, transmit) have the data we want to transmit. The data will be stored in the last byte of the
        timestamp field. 
    '''
    # ============= DETERMINE WHERE TO EMBED MESSAGE =============
    selector_bit = random.randint(0, 1) # if the selector is 0, message goes in "transmit timestamp"
                                        # if the selector is 1, message goes in "receive timestamp"

    ts_to_modify = "" # the timestamp attribute that we will modify. Either receive or transmit
    if selector_bit == 0: ts_to_modify = "recv"
    else: ts_to_modify = "sent"

    # ============= GENERATE CURRENT TIMESTAMP WITHOUT MESSAGE YET =============
    raw_time = time.time()
    time_now = raw_time + NTP_TIME_OFFSET # get the current time in UNIX 

    sec_part   = int(time_now)
    frac_part  = int((time_now - sec_part) * (1 << 32))  
    ntp_stamp  = (sec_part << 32) | frac_part # this is our current time in 64 bits and can be placed in any
                                                # of the timestamp fields. next, we put this value
                                                # in one of the timestamp fields and the last byte of this timestamp
                                                # field will have our message...

    # ============= CREATE EMBEDDED MESSAGE =============
    if msg_on: 
        embedded_msg = embed_msg_in_ts(ntp_stamp, msg[0], msg_on, selector_bit)
    else: 
        embedded_msg = ntp_stamp

    # # ============= CREATE ROOT DELAY ATTRIBUTE WITH CORRECT SETTINGS =============
    # root_delay = create_root_delay(msg_on, selector_bit)

    # ============= CREATE/SEND FINAL PACKET =============
    transport_layer = UDP(sport = port, dport = port)
    network_layer = IP(src = source, dst = destination)
    # application_layer = NTP(leap = 0, version = 4, mode = 3, delay = root_delay)
    # if ts_to_modify == "recv":
    #     application_layer.recv = embedded_msg
    # else:
    #     application_layer.sent = embedded_msg
    ntp_packet = network_layer / transport_layer / embedded_msg
    send(ntp_packet)

def extract_from_raw_payload(packet):
    """Extract the hidden bit and byte from UDP packet"""
    raw_data = None
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
    elif packet.haslayer('NTP'):
        try:
            udp_layer = packet[UDP]
            raw_data = bytes(udp_layer.payload)
        except Exception:
            pass

    # Error check
    if not raw_data or len(raw_data) < 32:
        return None, None

    try:
        # Unpack reference and originate timestamp fractions
        _, ref_fraction = struct.unpack('>II', raw_data[16:24])
        _, orig_fraction = struct.unpack('>II', raw_data[24:32])

        hidden_bit = ref_fraction & 0x1
        hidden_byte_raw = orig_fraction & 0xFF
        hidden_byte = hidden_byte_raw ^ NTP_PAD_KEY # UNPAD the hidden byte

        return hidden_bit, hidden_byte
    except Exception:
        return None, None

def packet_callback(pkt, my_ip):
    global message
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP]
        udp = pkt[UDP]
        if (udp.sport == 123 or udp.dport == 123) and ip.src != my_ip:
            hidden_bit, hidden_byte = extract_from_raw_payload(pkt)
            try:
                hidden_char = chr(hidden_byte) if 32 <= hidden_byte <= 126 else '.'
                if hidden_bit != 0: message += hidden_char 
            except Exception:
                hidden_char = '?'
            print(f"Hidden byte: {hidden_byte} ('{hidden_char}')")
            print("-" * 60)
            if not message_queue.empty():
                next_char = message_queue.get()
                print(f"[*] Sending queued byte back: '{next_char}'")
                send_fake_packets(my_ip, ip.src, 123, True, next_char)
                time.sleep(0.5)
                print("[*] Done responding one byte.")

            else:
                print(message)

def input_listener():
    # only prompt once
    try:
        msg = input("Enter message to send: ")
        for ch in msg:
            message_queue.put(ch)
    except KeyboardInterrupt:
        print("\n[!] Exiting...") 
    
def sender_loop(source_ip, target_ip, port):
    # block until someone calls .put() on message_queue
    while True:
        msg = message_queue.get() # this blocks until I enter a message
        print(f"[*] Sending queued message: '{msg}'")
        for ch in msg:
            send_fake_packets(source_ip, target_ip, port, True, ch)
            time.sleep(0.5)
        print("[*] Message send complete")

def main(): 

    # ============= GET THE OTHER PERSON'S IP =============
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print("[*] Other IP:", target_ip)
    print("[*] starting sender & receiver threads…")

    # # ============= START THE THREAD THAT WILL KEEP RECEIVING PACKETS =============
    # threading.Thread(target = receive_packets, args = (target_ip,), daemon = True).start()

    # ============= START THE THREAD WILL KEEP RUNNING input_listener TO POPULATE MY QUEUE =============
    threading.Thread(target = input_listener, daemon = True).start()

    # # # ============= START THE THREAD THAT WILL KEEP SENDING PACKETS FROM MY QUEUE =============
    # threading.Thread(target = sender_loop, args = (my_ip, target_ip, 123), daemon = True).start()

    try:
        sniff(filter="udp port 123", prn=lambda pkt: packet_callback(pkt, my_ip), store=False)
    except KeyboardInterrupt:
        print("\n[!] STOP")

    print("\n[+] Final Message:")
    print(message)

main() 
