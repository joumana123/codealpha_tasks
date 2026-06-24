import socket
import struct

# Create raw socket
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

host = socket.gethostbyname(socket.gethostname())
sniffer.bind((host, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("Network Sniffer Started...")
print("Press Ctrl + C to stop.\n")

try:
    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        # Extract first 20 bytes (IP Header)
        ip_header = raw_data[:20]

        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        protocol_num = iph[6]

        source_ip = socket.inet_ntoa(iph[8])
        destination_ip = socket.inet_ntoa(iph[9])

        # Detect protocol
        if protocol_num == 6:
            protocol = "TCP"
        elif protocol_num == 17:
            protocol = "UDP"
        elif protocol_num == 1:
            protocol = "ICMP"
        else:
            protocol = f"Other ({protocol_num})"

        print("\n" + "=" * 60)
        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Length  : {len(raw_data)} bytes")

        print("Payload:")
        print(raw_data[20:120])

except KeyboardInterrupt:
    print("\nStopping Sniffer...")
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)