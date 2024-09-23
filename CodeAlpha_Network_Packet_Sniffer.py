# Importing libraries needed
from scapy.all import sniff, Ether
import struct
import socket
import textwrap

# Packet Sniffer Main Code
def network_packet_sniffer():
    sniff(prn=process_packet)
    
# Unpack Ethernet Frame
def ethernet_frame_unpack(data):
    try:
        src_mac, dest_mac, protocol = struct.unpack('!6s6sH', data[:14])
        return get_mac_address(src_mac), get_mac_address(dest_mac), protocol, data[14:]  
    except struct.error as e:
        print("Error unpacking Ethernet frame: ", str(e))
        return None, None, None, None

# Human Readable Format MAC Address (i.e., AA:BB:CC:DD:EE:FF)
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 Packet with error handling and extensive debugging: 
def ipv4_packet_unpack(data):
    print("Entering ipv4_packet_unpack...")  # Debugging line
    
    try:
        # Ensure there's enough data to unpack
        if len(data) < 20:
            raise ValueError("Not enough data to unpack IPv4 header. Data length: {}".format(len(data)))

        # Extract the version and header length
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4

        print(f"Version: {version}, Header Length: {header_length}")  # Debugging line

        # Check if the header length is valid
        if header_length < 20:
            raise ValueError("Invalid header length: {}".format(header_length))

        # Unpack the IPv4 header (skip 8 bytes, unpack TTL, protocol, and 4-byte IP addresses)
        ttl, protocol, src, target = struct.unpack('!8xBB2x4s4s', data[:20])

        # Convert IP addresses to human-readable form
        src_ip = ipv4(src)
        dest_ip = ipv4(target)

        # Print unpacked values for debugging
        print(f"TTL: {ttl}, Protocol: {protocol}, Source IP: {src_ip}, Destination IP: {dest_ip}")

        # Return parsed values and remaining data after the header
        return version, header_length, ttl, protocol, src_ip, dest_ip, data[header_length:]

    except struct.error as e:
        print("Error unpacking IPv4 packet (struct error):", str(e))
        return None, None, None, None, None, None, None

    except Exception as e:
        print("An error occurred in ipv4_packet_unpack:", str(e))
        return None, None, None, None, None, None, None

# Join IP Address as a String 
def ipv4(address):
    return '.'.join(map(str, address))

# Main function with debugging
def process_packet(packet):
    if packet.haslayer(Ether):
        raw_data = bytes(packet)
        print("Raw packet data received")  # Debugging line
        try:
            dest_mac, src_mac, ethernet_protocol, data = ethernet_frame_unpack(raw_data)
            print(f"Ethernet Frame: Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {ethernet_protocol}")

            if ethernet_protocol == 0x0800:  # IPv4
                ipv4_info = ipv4_packet_unpack(data)
                
                # Check if IPv4 info was unpacked successfully
                if ipv4_info[0] is None:
                    print("Failed to unpack IPv4 packet")
                else:
                    version, header_length, ttl, protocol, src, target, data = ipv4_info
                    print(f"IPv4 Packet: Version: {version}, Source IP: {src}, Target IP: {target}")
                     # ICMP Protocol
                    if protocol == 1:
                        icmp_type, code, checksum, data = icmp_packet_unpack(data)
                        print('\tICMP Packet: ')
                        print('\t\tType: {}, Code:{}, Checksum: {}'.format(icmp_type, code, checksum))
                        print('\t\tData: ')
                        print(format_multiline_data('\t\t\t', data))
                
                    # TCP Protocol
                    elif protocol == 6:
                        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data) = tcp_segment(data)
                        print('\tTCP Segment: ')
                        print('\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
                        print('\t\tSequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                        print('\t\tFlags:')
                        print('\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin))
                        print('\t\tData: ')
                        print(format_multiline_data('\t\t\t', data))

                    # UDP Protocol
                    elif protocol == 17:
                        src_port, dest_port, length, data = udp_segment(data)
                        print('\tUDP Segment: ')
                        print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                        print(format_multiline_data('\t\t\t', data))
                     
                    else:
                        print('\tData: ')
                        print(format_multiline_data('\t\t', data))
                    
            else:
                print("Non-IPv4 packet")
                print("Data:")
                print(format_multiline_data('\t\t', data))
                
        except Exception as e:
            print("Error processing packet:", str(e))

# Unpack ICMP Packet:
def icmp_packet_unpack(data):
    if len(data) < 4:
        raise ValueError("ICMP packet must be at least 4 bytes")
    try:
        icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
        if icmp_type < 0 or icmp_type > 18:  # assuming ICMP types 0-18 are valid
            raise ValueError("Invalid ICMP type: {}".format(icmp_type))
        return icmp_type, code, checksum, data[4:]
    except struct.error as e:
        raise ValueError("Invalid ICMP packet format: {}".format(e))

# Unpack TCP Segment
def tcp_segment(data):
    if len(data) < 14:
        raise ValueError("TCP segment must be at least 14 bytes")
    try:
        src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
        if src_port < 0 or src_port > 65535:  # assuming port numbers 0-65535 are valid
            raise ValueError("Invalid source port: {}".format(src_port))
        if dest_port < 0 or dest_port > 65535:  # assuming port numbers 0-65535 are valid
            raise ValueError("Invalid destination port: {}".format(dest_port))
        offset = (offset_reserved_flags >> 12) * 4
        if offset > len(data):
            raise ValueError("Invalid offset: {}".format(offset))
    except struct.error as e:
        raise ValueError("Invalid TCP segment format: {}".format(e))
    flags_urg = (offset_reserved_flags & 32) >> 5
    flags_ack = (offset_reserved_flags & 16) >> 4
    flags_psh = (offset_reserved_flags & 8) >> 3
    flags_rst = (offset_reserved_flags & 4) >> 2
    flags_syn = (offset_reserved_flags & 2) >> 1
    flags_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, offset_reserved_flags, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data[offset:]

# Unpack UDP Segment 
def udp_segment(data):
    if len(data) < 8:
        raise ValueError("UDP segment must be at least 8 bytes")
    src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
    return  src_port, dest_port, size, data[8:]

# Format Multi-line Data
def format_multiline_data(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

network_packet_sniffer()

