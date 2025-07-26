from scapy.all import *
from scapy.layers.ntp import NTP
import time
import sys
import random

NTP_TIME_OFFSET = 2208988800

def create_root_delay(msg_on, selector): 
    '''
        args: 
            - msg_on: whether we are actually sending a message or not
            - selector: which timestamp to use if the message is on
        return: The new root delay with the first two bits modified.
        This function takes a root delay value and makes the first bit represent whether a message is in the 
        packet and the second bit represent which timestamp attribute the message is in.
    '''
    base_delay = 0x00010200 # start with 0x00010200 for the "root delay" value because most delays are between 0.5 & 1ms
                            # so 1.01 ms seems believable

    # first, we zero out the last two bits
    #   0x FF FF FF FC    (C = 1100)
    # | 0x 00 01 02 00
    # = 0x 00 01 02 00
    base_delay = base_delay | 0xFFFFFFFC

    # second, we need to make the first bit have the value of msg_on
    base_delay = base_delay | msg_on

    # third, we need to make the second bit have the value of the selector
    base_delay = base_delay | selector << 1 

    # third, we place the two bit selector and msg_on at the end of the base_delay and return it
    return base_delay

def embed_msg_in_ts(timestamp, msg):
    '''
        args: 
            - timestamp: the timestamp we are embedding a message within
            - msg: the message we are embedding
        return: Timestamp where last byte is the message
        This function takes a timestamp and embeds the message in the last byte of the timestamp
    '''
    
    # first, zero-out the last byte (2 hex digits) of the timestamp
    #   0x FF FF FF FF FF FF FF 00
    # & __ __ __ __ __ __ __ __ 00 
    # = __ __ __ __ __ __ __ __ 00
    timestamp = timestamp & 0xFFFFFFFFFFFFFF00

    # second, OR the result with the message to set the last byte
    #   0x FF FF FF FF FF FF FF 00
    # | __ __ __ __ __ __ __ __ msg 
    # = __ __ __ __ __ __ __ __ msg
    timestamp = timestamp | msg

    return timestamp

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
        embedded_msg = embed_msg_in_ts(ntp_stamp, ord(msg[0]))
    else: 
        embedded_msg = ntp_stamp

    # ============= CREATE ROOT DELAY ATTRIBUTE WITH CORRECT SETTINGS =============
    root_delay = create_root_delay(msg_on, selector_bit)

    # ============= CREATE/SEND FINAL PACKET =============
    transport_layer = UDP(sport = port, dport = port)
    network_layer = IP(src = source, dst = destination)
    application_layer = NTP(leap = 0, version = 4, mode = 3, delay = root_delay)
    if ts_to_modify == "recv":
        application_layer.recv = embedded_msg
    else:
        application_layer.sent = embedded_msg
    ntp_packet = network_layer / transport_layer / application_layer
    send(ntp_packet)

def main(): 

    send_fake_packets("192.168.12.250", "192.168.13.4", 123, True, msg = "H")

main() 
