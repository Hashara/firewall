#!usr/bin/python3
import socket
import struct


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, ethernet_proto, data = ethernet_frame(raw_data)
        print("\nEthernet frame")
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_proto))

        # IPv4 ethernet proto = 8
        if ethernet_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print("\t" + "IPv4 packet: ")
            print("\t\t" + "source ip: {} destination ip: {}".format(src, target))

            ''' proto type
                    6 TCP
                    17 UDP
            '''
            # TCP
            if proto == 6:
                print("TCP")
                src_port, dest_port = tcp_segment(data)
                print("\t\t\t" + "source port : {} destination port: {}".format(src_port, dest_port))

            # UDP
            elif proto == 17:
                src_port, dest_port = udp_segment(data)
                print("UDP")
                print("\t\t\t" + "source port : {} destination port: {}".format(src_port, dest_port))


# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # destination, source, ethernet type, payload
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]


def get_mac_addr(byte_address):
    byte_string = map('{:02x}'.format, byte_address)
    return ':'.join(byte_string).upper()


# unpack Ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# format ipv4 10.10.10.10
def ipv4(address):
    return '.'.join(map(str, address))


# Unpack TCP
def tcp_segment(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port


# Unpack UDP
def udp_segment(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port


main()
