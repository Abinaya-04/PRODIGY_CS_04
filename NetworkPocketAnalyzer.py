import socket
import struct
import binascii

# Create a raw socket
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Bind the socket to a network interface
sock.bind(('eth0', 0))

# Set up the socket to capture all packets
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

print("Packet Sniffer Tool")

while True:
    # Capture a packet
    packet = sock.recvfrom(65565)[0]

    # Unpack the Ethernet header
    eth_header = struct.unpack('!6s6sH', packet[:14])
    eth_src = binascii.hexlify(eth_header[0])
    eth_dst = binascii.hexlify(eth_header[1])
    eth_type = eth_header[2]

    # Unpack the IP header
    ip_header = struct.unpack('!BBHHHBBHLL', packet[14:34])
    ip_src = socket.inet_ntoa(struct.pack('!I', ip_header[8]))
    ip_dst = socket.inet_ntoa(struct.pack('!I', ip_header[9]))
    ip_proto = ip_header[6]

    # Unpack the TCP header
    tcp_header = struct.unpack('!HHLLBBHHH', packet[34:54])
    tcp_src_port = tcp_header[0]
    tcp_dst_port = tcp_header[1]
    tcp_seq = tcp_header[2]
    tcp_ack = tcp_header[3]
    tcp_flags = tcp_header[5]

    # Print packet information
    print("Ethernet:")
    print(" Source:", eth_src)
    print(" Destination:", eth_dst)
    print(" Type:", eth_type)
    print("IP:")
    print(" Source:", ip_src)
    print(" Destination:", ip_dst)
    print(" Protocol:", ip_proto)
    print("TCP:")
    print(" Source Port:", tcp_src_port)
    print(" Destination Port:", tcp_dst_port)
    print(" Sequence Number:", tcp_seq)
    print(" Acknowledgment Number:", tcp_ack)
    print(" Flags:", tcp_flags)
    print("Payload:")
    print(packet[54:])

    # Break the loop
    break