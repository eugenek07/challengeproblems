# Covert Communications

**Throughput:** 1 Byte/Packet and 1 Packet/64 Seconds

In order to receive information to and from the C2 and LAN, the connection is modeled around standard NTP time synchronization connections. Therefore, the NTP server only sends responses once a request is sent.

---

## Begin Covert Comms

- Run `python3 client.py` from the **LAN machine**  
- Run `python3 server.py` from the **C2 machine** on the target network

---

## No Messages / Only NTP Request and Response

Once running, `client.py` sends an NTP request to the C2 every 64 seconds.

- **No message being sent:**  
  ```ReferenceField[31] = 0```

`server.py` on the C2 machine responds each time it receives a request.

- **No message being sent:**  
  ```RootDelay[31] = 0```

The '0' bit indicates that no message is currently being sent.
---

## Message from C2 → LAN

Type a message in the terminal running `client.py`:

```
I love ACE!
```

It gets stored in the payload’s personal **queue**, ordered into bytes (Last In, First Out). Every 64 seconds, it sends one XOR’ed byte from the above string.

- **Message Sent Indicator:**  
  ```ReferenceField[31] = 1```
- **Byte Stored in NTP:**
   ```OriginTimestamp[7] = <byte(Message)>```

The server (`server.py`) reads one byte at a time, deciphers it (XOR), and adds it to a list of bytes to eventually format as a string output.

---

## Message from LAN → C@

Type a message in the terminal running `server.py`:

```
I adore ChaP!
```

It gets stored in `server.py`'s personal **queue**, ordered into bytes (Last In, First Out). Each byte is sent one at a time, every 64 seconds.

- **If message is being sent:**  
  ```RootDelay[30] = 1```

- **If message is stored in:**  
  ```ReceiveTimestamp[7] = <byte(Message)>```  
  then  
  ```RootDelay[31] = 1```

- **If message is stored in:**  
  ```TransmitTimestamp[7] = <byte(Message)>```  
  then  
  ```RootDelay[31] = 0```

`client.py` reads each byte, XORs it, stores the result in a list, and finally outputs the reconstructed message as a string.

