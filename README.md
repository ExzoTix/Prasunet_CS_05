# TASK-05 Network Packet Analyzer
- Here we have to develop a packet sniffer tool that captures and analyzes network packets. We have to display relevant information such as source and destination IP addresses, protocols, and payload data.
- **Note: Ensure the ethical use of the tool for educational purposes.**
- We have to install **Scapy** in Python using pip.
- Please find the python program **network_packet_analyzer.py** attached.

# Network Packet
A network packet is a formatted unit of data that is transmitted across a network. It contains both the data to be sent and control information such as the source and destination addresses, which are necessary for proper routing and delivery.

**Components of a Network Packet**

1. **Header**: The header contains control information that ensures the packet reaches its intended destination and is properly assembled at the receiving end. Key components of the header include:
   - **Source IP Address**: The IP address of the device sending the packet.
   - **Destination IP Address**: The IP address of the device intended to receive the packet.
   - **Protocol Information**: Indicates the protocol used, such as TCP, UDP, or ICMP.
   - **Port Numbers**: Specify the application-layer protocols (e.g., HTTP, FTP) or services the packet is associated with.
   - **Sequence Number**: Helps in reassembling packets in the correct order when they are received.
   - **Checksum**: Ensures data integrity by allowing error checking of the packet.

2. **Payload**: The payload is the actual data being transmitted, such as part of a web page, an email, or a file fragment. The size of the payload can vary depending on the network's configuration and the data being sent.

3. **Trailer**: Some protocols include a trailer that can contain error-checking data like a Frame Check Sequence (FCS) to ensure the packet has not been corrupted during transmission.

**Diagram of a Packet Structure**
```
+-----------------------------------------+
|                Header                   |
|      (e.g., IP, TCP/UDP headers)        |
+-----------------------------------------+
|                Payload                  |
|     (Actual data, e.g., HTTP data)      |
+-----------------------------------------+
|                Trailer                  |
|      (e.g., Frame Check Sequence)       |
+-----------------------------------------+
```

**Types of Packets**

1. **IP Packets**: The fundamental unit in the Internet Protocol (IP), used to transmit data between devices over the internet.

2. **TCP Packets**: Used in the Transmission Control Protocol (TCP), providing reliable data transmission with error checking and flow control.

3. **UDP Packets**: Used in the User Datagram Protocol (UDP), allowing faster transmission with no guaranteed delivery.

4. **ICMP Packets**: Used by the Internet Control Message Protocol (ICMP) for diagnostic and control purposes, such as the `ping` command.
