# Covert Communications
Throughput = 1 Byte/Packet and 1 Packet/64 Seconds

In order to receive information to and from the C2 and LAN, the connection is modelled around standard NTP time syncrhonization connections. Therefore, the NTP server only sends responses once a request is sent. 

## Begin Covert Comms
Run ```python3 c2.py``` from the C2 machine
Run ```python3 payload.py``` from the LAN machine on the target network

## No Messages/ Only NTP Request and Response
Once running, the payload.py will send an NTP request to the LAN machine once every 64 seconds. 
    - No message being sent: ```ReferenceField[31] = 0```
c2.py on the C2 machine responds once every time it gets the request.
    - No message being sent: ```RootDelay[31] = 0 ```

## Message from LAN -> C2
Type a message onto terminal of the running process of payload.py:
    ```I love ACE!```
It gets stored in the payload's personal QUEUE ordered into bytes (Last In First Out)
Every 64 seconds, it sends one 'xor'ed byte from the above string
    - Message being sent: ```ReferenceField[31] = 1```
The server will read one byte at a time, deciphering it ('xor'ing it) and adding it to a list of bytes to finally format as a string output

## Message from C2 -> LAN
Type a message onto terminal of the running process of c2.py
    ```I adore ChaP!```
It gets stored in the c2.py's personal QUEUE ordered into bytes (Last in First Out), sending each byte one at a time every 64 seconds. 
Every 64 seconds, it sends one 'xor'ed byte from the above string
    - If Message being sent: ```RootDelay[30] = 1```
    - If message stored in ```ReceiveTimestamp[7] = <byte(Message)>```
        - ```RootDelay[31] = 1```
    - If message stored in ```TransmitTimestamp[7] = <byte(Message)>```
        - ```RootDelay[31] = 0```
The payload.py reads each byte 'xor'ing it, storing them onto a list, and finally outputs as a string output

