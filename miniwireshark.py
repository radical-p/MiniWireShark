import socket
from struct import *
from socket import htons

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def ethernet_frame(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def ipv4_packet(data):
    version_internet_header_length = data[0]
    version = version_internet_header_length >> 4
    internet_header_length = (version_internet_header_length & 15) * 4
    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, internet_header_length, ttl, proto, ipv4(src), ipv4(target), data[internet_header_length:]


def tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def ethernet_frame(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    
    bytes_str = map('{:02x}'.format, dest_mac)
    dest_mac_address = ':'.join(bytes_str).upper()
    
    bytes_str = map('{:02x}'.format, src_mac)
    src_mac_address = ':'.join(bytes_str).upper()
    
    return dest_mac_address, src_mac_address, htons(proto), data[14:]


while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, ethernet_protocol, data = ethernet_frame(raw_data)

    if ethernet_protocol == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

        if proto == 6:# just capture my packets
                (src_port, dest_port, sequence, ack, urg, flagAck, flagpsh, flagRst, flagSyn, flagFin, data) = tcp_segment(data)
                if(flagAck == 1 and flagSyn == 1):
                    print('\tSYN-ACK packet recieved:')
                    print(f'\tSource Port: {src_port} / Destination Port: {dest_port}')
