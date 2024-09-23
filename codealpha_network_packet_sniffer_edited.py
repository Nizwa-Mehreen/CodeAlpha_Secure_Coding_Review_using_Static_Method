# Importing required libraries
import struct
import textwrap
from scapy.all import sniff, Ether

# Packet Sniffer Main Code
def network_packet_sniffer():
    """Main function to sniff packets."""
    sniff(prn=process_packet)

# Unpack Ethernet Frame
def ethernet_frame_unpack(data):
    """Unpacks the Ethernet frame."""
    try:
        src_mac, dest_mac, protocol = struct.unpack('!6s6sH', data[:14])
        return get_mac_address(src_mac), get_mac_address(dest_mac), protocol, data[14:]
    except struct.error as e:
        print(f"Error unpacking Ethernet frame: {str(e)}")
        return None, None, None, None

# Human-readable format MAC Address (i.e., AA:BB:CC:DD:EE:FF)
def get_mac_address(bytes_address):
    """Converts a MAC address to human-readable format."""
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 Packet
def ipv4_packet_unpack(data):
    """Unpacks the IPv4 packet with error handling."""
    try:
        if len(data) < 20:
            raise ValueError(f"Not enough data to unpack IPv4 header. Data length: {len(data)}")

        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4

        if header_length < 20:
            raise ValueError(f"Invalid header length: {header_length}")

        ttl, protocol, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
        src_ip = ipv4(src)
        dest_ip = ipv4(target)

        return version, header_length, ttl, protocol, src_ip, dest_ip, data[header_length:]
    except struct.error as e:
        print(f"Error unpacking IPv4 packet: {str(e)}")
        return None, None, None, None, None, None, None
    except Exception as e:
        print(f"An error occurred in ipv4_packet_unpack: {str(e)}")
        return None, None, None, None, None, None, None

# Converts IP Address to String
def ipv4(address):
    """Converts an IP address to a human-readable format."""
    return '.'.join(map(str, address))

# Main function with debugging
def process_packet(packet):
    """Processes each packet."""
    if packet.haslayer(Ether):
        raw_data = bytes(packet)
        try:
            dest_mac, src_mac, ethernet_protocol, data = ethernet_frame_unpack(raw_data)
            print(f"Ethernet Frame: Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {ethernet_protocol}")

            if ethernet_protocol == 0x0800:  # IPv4
                ipv4_info = ipv4_packet_unpack(data)
                if ipv4_info[0] is not None:
                    version, header_length, ttl, protocol, src, target, data = ipv4_info
                    print(f"IPv4 Packet: Version: {version}, Source IP: {src}, Target IP: {target}")

                    # Handle different protocols
                    if protocol == 1:
                        icmp_type, code, checksum, data = icmp_packet_unpack(data)
                        print(f"\tICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                        print(f"\tData: {format_multiline_data('\t\t', data)}")

                    elif protocol == 6:
                        tcp_segment_info = tcp_segment(data)
                        print(f"\tTCP Segment: Source Port: {tcp_segment_info[0]}, Destination Port: {tcp_segment_info[1]}")
                        print(f"\tFlags: URG: {tcp_segment_info[5]}, ACK: {tcp_segment_info[6]}, PSH: {tcp_segment_info[7]}, RST: {tcp_segment_info[8]}, SYN: {tcp_segment_info[9]}, FIN: {tcp_segment_info[10]}")
                        print(f"\tData: {format_multiline_data('\t\t', tcp_segment_info[11])}")

                    elif protocol == 17:
                        udp_segment_info = udp_segment(data)
                        print(f"\tUDP Segment: Source Port: {udp_segment_info[0]}, Destination Port: {udp_segment_info[1]}, Length: {udp_segment_info[2]}")
                        print(f"\tData: {format_multiline_data('\t\t', udp_segment_info[3])}")

                    else:
                        print(f"\tData: {format_multiline_data('\t\t', data)}")
                else:
                    print("Failed to unpack IPv4 packet")
            else:
                print("Non-IPv4 packet")
        except Exception as e:
            print(f"Error processing packet: {str(e)}")

# Unpack ICMP Packet
def icmp_packet_unpack(data):
    """Unpacks the ICMP packet."""
    if len(data) < 4:
        raise ValueError("ICMP packet must be at least 4 bytes")
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP Segment
def tcp_segment(data):
    """Unpacks the TCP segment."""
    if len(data) < 14:
        raise ValueError("TCP segment must be at least 14 bytes")
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags_urg = (offset_reserved_flags & 32) >> 5
    flags_ack = (offset_reserved_flags & 16) >> 4
    flags_psh = (offset_reserved_flags & 8) >> 3
    flags_rst = (offset_reserved_flags & 4) >> 2
    flags_syn = (offset_reserved_flags & 2) >> 1
    flags_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, offset_reserved_flags, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data[offset:]

# Unpack UDP Segment
def udp_segment(data):
    """Unpacks the UDP segment."""
    if len(data) < 8:
        raise ValueError("UDP segment must be at least 8 bytes")
    src_port, dest_port, length = struct.unpack('!HH2xH', data[:8])
    return src_port, dest_port, length, data[8:]

# Format Multi-line Data
def format_multiline_data(prefix, string, size=80):
    """Formats data for multiline output."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

network_packet_sniffer()
