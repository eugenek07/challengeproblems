import socket
from scapy.all import * # used to create fake but realistic packets to send to the receiver
import random

def send_fake_packets(data, host, dest, port): 
    '''
        This function will create fake HTTP packets (i.e., TCP packets with HTTP data) and will send the 
        packet to the receiver. This packet has two special features: 
        --> "data offset" attribute contains a value: 00, 01, 10, or 11. This value is the byte number
        in the "sequence number" attribute of the TCP header that will contain our data
        --> One of four bytes in the "sequence number" contains data that we are sending to the receiver 
    '''

    value = 0x41  # ASCII 'A'
    selector = 2

    seq_bytes = [0, 0, 0, 0]
    seq_bytes[selector] = value
    seq = (seq_bytes[0]<<24) | (seq_bytes[1]<<16) | (seq_bytes[2]<<8) | seq_bytes[3]

    ip  = IP(src=host, dst=dest)
    syn = TCP(sport=RandShort(), dport=port, flags="S", seq=seq)
    
    # create the SYN packet
    syn_packet = ip/syn

    # send a SYN packet, wait for a SYN-ACK from the receiver..
    syn_ack = sr1(syn_packet, timeout=1, verbose=0)
    if not syn_ack or syn_ack[TCP].flags != 0x12: # 0x12 = SYN/ACK
        print("No SYN/ACK... port closed")
        return

    # send an ACK packet if received SYN/ACK..
    ack = TCP(sport=syn.sport, dport=port, flags="A", seq=syn.seq+1, ack=syn_ack.seq+1)
    ack_packet = ip/ack
    send(ack_packet, verbose=0)

    # send a PSH/ACK with the HTTP-like data..
    http = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
    psh  = TCP(sport=syn.sport, dport=port, flags="PA", seq=ack.seq, ack=ack.ack)
    http_packet = ip/psh/http
    send(http_packet, verbose=0)

# def send_data(data, host, port):
#     """
#     This function sends data from a buffer over TCP to the specified host and port.
#     :param data: The data to be sent.
#     :param host: The host to send the data to.
#     :param port: The port to send the data to.
#     """
#     # Create a TCP/IP socket
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     # Connect the socket to the host and port
#     server_address = (host, int(port))
#     sock.connect(server_address)

#     try:
#         # Send data
#         # encode() converts string to bytes to send over the wire
#         sock.sendall(data.encode('utf-8'))
#         print("Data sent: " + data)
#     finally:
#         # Close the socket
#         sock.close()

def main():
    # host variable is hardcoded to localhost (127.0.0.1), port is hardcoded to 8080
    # data is set to the single character "A"
    # Try changing these values or even allowing the user to input them at runtime or on the command line
    # send_data("A", "127.0.0.1", "8080")
    #send_fake_packets("A", "192.168.13.4", "192.168.12.250", "8080")
    send_fake_packets("A", "192.168.13.4", "192.168.12.250", 8080)
main()

#from scapy.all import *

# Covert byte
#value = 0x41  # ASCII 'A'
#selector = 2

# Encode in seq number
#seq_bytes = [0, 0, 0, 0]
#seq_bytes[selector] = value
#seq_value = (seq_bytes[0]<<24) | (seq_bytes[1]<<16) | (seq_bytes[2]<<8) | seq_bytes[3]

#pkt = IP(src="192.168.1.100", dst="192.168.1.101") / \
#     TCP(sport=12345, dport=8080, flags="PA", seq=seq_value)

#send(pkt)