from ipaddress import IPv4Address
from sqlite3 import connect
from packet_struct import *
from struct import *
import sys
import math
import threading

#Note most code will not work with big endian specifically packet_struct I have not updated the script yet.

def main(filename):
    cap_file = open(filename, "rb")
    sys.stdout = open("Output.txt", "w")
    glob = cap_file.read(24)

    global endian 
    endian = '<'
    #check endianess
    magic_num = glob[0:2]
    if magic_num == 0xa1b2c3d4:
        endian = '>'
    inc_len_format = endian + "I"

    pack_num = 0
    packet_head = cap_file.read(16)
    ICMP_packets = []
    ICMP_echo_packets = []
    UDP_packets = []
    windows = False

    cap_time_sec = packet_head[0:4]
    cap_time_msec = packet_head[4:8]
    this_zone = packet_head[8:12]
    cur_pack = packet()
    cur_pack.timestamp_set(cap_time_sec, cap_time_msec, 0, endian)
    orig_time = cur_pack.timestamp

    while(len(packet_head) > 15):
        pack_num += 1
        cap_time_sec = packet_head[0:4]
        cap_time_msec = packet_head[4:8]
        this_zone = packet_head[8:12]
        #Packet header info
        cur_pack = packet()
        cur_pack.packet_No_set(pack_num)
        cur_pack.timestamp_set(cap_time_sec, cap_time_msec, orig_time, endian)
        inc_len = unpack(inc_len_format, packet_head[8:12])
        packet_data = cap_file.read(inc_len[0])
        #ethernet header
        eth_header = packet_data[0:14]
        #IPv4 Header
        IPV4 = get_packet_IPV4(packet_data, cur_pack)

        if(IPV4[1] == 1):
            cur_ICMP_header = ICMP_Header()
            ICMP_header = packet_data[(14 + IPV4[0]):(14 + IPV4[0] + 8)]
            cur_ICMP_header.get_type(ICMP_header[0:1])
            #echo request
            if(cur_ICMP_header.type == 8):
                windows = True
            
            #for linux all ICMP should not be from source
            if(windows):
                #echo reply/request
                if(cur_ICMP_header.type == 8 or cur_ICMP_header.type == 0):
                    cur_ICMP_header.get_echo_seq_num(ICMP_header[6:8])
                    cur_pack.ICMP_header = cur_ICMP_header
                    #reply from dest, request from src
                    if cur_ICMP_header.type == 0:
                        ICMP_packets.append(cur_pack)
                    else:
                        ICMP_echo_packets.append(cur_pack)
                #expired/unreachable
                elif(cur_ICMP_header.type == 11 or cur_ICMP_header.type == 3):
                    IPV4_header = packet_data[(14 + IPV4[0] + 8):(14 + IPV4[0] + 28)]
                    IPV4_head_len = (struct.unpack('B', IPV4_header[0:1])[0]& 15)*4
                    echo_ICMP_data = packet_data[(14 + 8 + IPV4_head_len + IPV4[0]):(14 + 8 + IPV4_head_len + IPV4[0] + 14)]
                    cur_ICMP_header.get_echo_seq_num(echo_ICMP_data[6:8])
                    cur_ICMP_header.get_IP(IPV4_header[12:16], IPV4_header[16:20])
                    cur_pack.ICMP_header = cur_ICMP_header
                    ICMP_packets.append(cur_pack)
            elif(cur_ICMP_header.type == 11 or cur_ICMP_header.type == 3):
                IPV4_header = packet_data[(14 + IPV4[0] + 8):(14 + IPV4[0] + 28)]
                IPV4_head_len = (struct.unpack('B', IPV4_header[0:1])[0]& 15)*4
                cur_ICMP_header.get_IP(IPV4_header[12:16], IPV4_header[16:20])
                UDP_header = packet_data[(14 + IPV4[0] + 8 + IPV4_head_len):(14 + IPV4[0] + 8 + IPV4_head_len + 8)]
                cur_ICMP_header.get_UDP_src_port(UDP_header[0:2])
                cur_ICMP_header.get_UDP_dst_port(UDP_header[2:4])
                if cur_pack.IP_header.frag_offset == 0:
                    if cur_ICMP_header.UDP_dst_port < 33434 or cur_ICMP_header.UDP_dst_port > 33529:
                        packet_head = cap_file.read(16)
                        continue
                cur_pack.ICMP_header = cur_ICMP_header
                ICMP_packets.append(cur_pack)
        elif(IPV4[1] == 17):
            UDP_header = packet_data[(14 + IPV4[0]):(14 + IPV4[0] + 8)]
            cur_UDP_header = UDP_Header()
            cur_UDP_header.get_src_port(UDP_header[0:2])
            cur_UDP_header.get_dst_port(UDP_header[2:4])
            #couldn't get the correct port of fragments so used this if to ensure the fragments were added
            if cur_pack.IP_header.frag_offset == 0:
                if cur_UDP_header.dst_port < 33434 or cur_UDP_header.dst_port > 33529:
                    packet_head = cap_file.read(16)
                    continue
            cur_pack.UDP_header = cur_UDP_header
            UDP_packets.append(cur_pack)
        packet_head = cap_file.read(16)

    if windows:
        list_addresses_win(ICMP_packets, ICMP_echo_packets, UDP_packets)
    else:
        list_addresses(ICMP_packets, UDP_packets)

    return

#get IPV4 packet header data
def get_packet_IPV4(packet_data, cur_pack):
    cur_IP_header = IP_Header()
    IP_header = packet_data[14:34]

    cur_IP_header.get_header_len(IP_header[0:1])
    cur_IP_header.get_total_len(IP_header[2:4])
    cur_IP_header.get_identification(IP_header[4:6])
    cur_IP_header.get_flags_offset(IP_header[6:8])
    cur_IP_header.get_ttl(IP_header[8:9])
    cur_IP_header.get_protocol(IP_header[9])
    cur_IP_header.get_IP(IP_header[12:16], IP_header[16:20])
    cur_pack.IP_header = cur_IP_header
    return (cur_IP_header.ip_header_len, cur_IP_header.protocol, cur_IP_header.total_len)

#Gets intermediade_routers for windows trace files then calls get_rtts_win
def list_addresses_win(ICMP_packets, ICMP_echo_packets, UDP_packets):
    intermediade_routers = []
    dest_ip = ICMP_packets[0].ICMP_header.dst_ip
    src_dest_packets = []

    for packet in ICMP_packets + ICMP_packets:
        cur_src_seq = packet.ICMP_header.echo_seq_num
        for searchPacket in ICMP_echo_packets:
            #check if a packet returned ICMP 70
            if(cur_src_seq == searchPacket.ICMP_header.echo_seq_num):
                #check if ip already in list
                in_list = False
                in_src_dst_list = False
                ip = packet.IP_header.src_ip
                if ip == dest_ip:
                    for curip in src_dest_packets:
                        if curip.IP_header.src_ip == ip:
                            in_src_dst_list = True
                    if not in_src_dst_list:
                        src_dest_packets.append(packet)
                    continue
                for curip in intermediade_routers:
                    if curip.IP_header.src_ip == ip:
                        in_list = True
                if not in_list:
                    packet.hop_count = searchPacket.IP_header.ttl
                    intermediade_routers.append(packet)
                break

    intermediade_routers.sort(key=lambda x: x.hop_count)
    print("The IP address of the source node: ", ICMP_packets[0].ICMP_header.src_ip)
    print("The IP address of the destination node: ", dest_ip)
    if(len(intermediade_routers) > 0):
        print("The IP addresses of the intermediate destination nodes: ")
        i = 1
        for packet in intermediade_routers:
            print("    router ", i, ": ", packet.IP_header.src_ip)
            i = i + 1
    print("")
    print_protcols(ICMP_packets, UDP_packets)
    print_frag_data_win(ICMP_echo_packets)
    get_rtts_win(ICMP_echo_packets, ICMP_packets, intermediade_routers, src_dest_packets)
    return

#Gets intermediade_routers for linux trace files then calls get_rtts
def list_addresses(ICMP_packets, UDP_packets):
    intermediade_routers = []
    src_dest_packets = []
    dest_ip = ICMP_packets[0].ICMP_header.dst_ip

    for packet in ICMP_packets:
        cur_src_port = packet.ICMP_header.UDP_src_port
        for searchPacket in UDP_packets:
            #check for fragments
            if(cur_src_port == searchPacket.UDP_header.src_port):
                #check if ip already in list
                in_list = False
                in_src_dst_list = False
                ip = packet.IP_header.src_ip
                if ip == dest_ip:
                    for curip in src_dest_packets:
                        if curip.IP_header.src_ip == ip:
                            in_src_dst_list = True
                    if not in_src_dst_list:
                        src_dest_packets.append(packet)
                    continue
                for curip in intermediade_routers:
                    if curip.IP_header.src_ip == ip:
                        in_list = True
                if not in_list:
                    packet.hop_count = searchPacket.IP_header.ttl
                    intermediade_routers.append(packet)
                break
    src_ip = ICMP_packets[0].ICMP_header.src_ip
    intermediade_routers.sort(key=lambda x: x.hop_count)
    print("The IP address of the source node: ", src_ip)
    print("The IP address of the destination node: ", dest_ip)
    if(len(intermediade_routers) > 0):
        print("The IP addresses of the intermediate destination nodes: ")
        i = 1
        for packet in intermediade_routers:
            print("    router ", i, ": ", packet.IP_header.src_ip)
            i = i + 1
    print("")
    print_protcols(ICMP_packets, UDP_packets)
    print_frag_data(UDP_packets)
    get_rtts(UDP_packets, ICMP_packets, intermediade_routers, src_dest_packets)
    return

#prints protocols that appear in the trace (UDP or ICMP)
def print_protcols(ICMP_packets, UDP_packets):
    print("The values in the protocol field of IP headers:")
    if ICMP_packets:
        print("    1: ICMP")
    if UDP_packets:
        print("    17: UDP")
    print("")
    return

#get fragmented data for windows
def print_frag_data_win(ICMP_echo_packets):
    frags = []
    frag_count = 1
    prev_offset = 0
    for packet in ICMP_echo_packets:
        if(packet.IP_header.frag_offset == 0 and packet.ICMP_header.type == 8):
            cur_id = packet.IP_header.identification
            for other_packets in ICMP_echo_packets:
                if(other_packets.IP_header.identification == cur_id and other_packets.IP_header.frag_offset != prev_offset):
                    frag_count += 1
                    prev_offset = other_packets.IP_header.frag_offset
                    
            frags.append((cur_id, frag_count, prev_offset))
            frag_count = 1
            prev_offset = 0

    for frag in frags:
        print("The number of fragments created from the original datagram with id ", frag[0], " is: ", frag[1])
        print("The offset of the last fragment is: ", frag[2])
        print("")
    return

#get fragmentented data for linux
def print_frag_data(UDP_packets):
    frags = []
    frag_count = 1
    prev_offset = 0
    for packet in UDP_packets:
        #print(packet.IP_header.identification)
        if(packet.IP_header.frag_offset == 0):
            cur_id = packet.IP_header.identification
            for other_packets in UDP_packets:
                if(other_packets.IP_header.identification == cur_id and other_packets.IP_header.frag_offset != prev_offset):
                    frag_count += 1
                    prev_offset = other_packets.IP_header.frag_offset
            frags.append((cur_id, frag_count, prev_offset))
            prev_offset = 0
            frag_count = 1
    
    for frag in frags:
        print("The number of fragments created from the original datagram with id ", frag[0], " is: ", frag[1])
        print("The offset of the last fragment is: ", frag[2])
        print("")
    return

#gets the RTTS for a windows tracefile (including host to destination)
def get_rtts_win(ICMP_echo_packets, ICMP_packets, intermediade_routers, src_dest_packets, flag=False):
    rtts = []
    src_ip = ICMP_packets[0].ICMP_header.src_ip
    icmp_data = []

    for echo_packet in ICMP_echo_packets:
        seq_num = echo_packet.ICMP_header.echo_seq_num
        for icmp_packet in ICMP_packets:
            if(seq_num == icmp_packet.ICMP_header.echo_seq_num):
                icmp_data.append((echo_packet, icmp_packet))
                rtts.append((icmp_packet.timestamp-echo_packet.timestamp, icmp_packet.IP_header.src_ip))
    
    frag_id = -1
    for echo_packet in ICMP_echo_packets:
        if echo_packet.IP_header.flags == 0x20 and echo_packet.IP_header.frag_offset == 0:
            frag_id = echo_packet.IP_header.identification
        if frag_id == echo_packet.IP_header.identification:
            #find corresponding entry in rtts
            for other_packet in icmp_data:
                if other_packet[0].IP_header.identification == frag_id:
                    rtts.append((other_packet[1].timestamp - echo_packet.timestamp, other_packet[1].IP_header.src_ip))
                    break
    
    print_RTT(src_ip, intermediade_routers, rtts)
    #get src to dest RTT
    if not flag:
        get_rtts_win(ICMP_echo_packets, ICMP_packets, src_dest_packets, src_dest_packets, True)
    return

#gets the RTTS for a linux tracefile (including host to destination)
def get_rtts(UDP_packets, ICMP_packets, intermediade_routers, src_dest_packets, flag=False):
    rtts = []
    src_ip = ICMP_packets[0].ICMP_header.src_ip
    udp_icmp_data = []
    for udp_packet in UDP_packets:
        src_port = udp_packet.UDP_header.src_port
        for icmp_packet in ICMP_packets:
            if(src_port == icmp_packet.ICMP_header.UDP_src_port):
                udp_icmp_data.append((udp_packet, icmp_packet))
                rtts.append((icmp_packet.timestamp-udp_packet.timestamp, icmp_packet.IP_header.src_ip))
    frag_id = -1
    for udp_packet in UDP_packets:
        if udp_packet.IP_header.flags == 0x20 and udp_packet.IP_header.frag_offset == 0:
            frag_id = udp_packet.IP_header.identification
        if frag_id == udp_packet.IP_header.identification:
            #find corresponding entry in rtts
            for other_packet in udp_icmp_data:
                if other_packet[0].IP_header.identification == frag_id:
                    rtts.append((other_packet[1].timestamp - udp_packet.timestamp, other_packet[1].IP_header.src_ip))
                    break

    print_RTT(src_ip, intermediade_routers, rtts)
    
    #get src to dest RTT
    if not flag:
        get_rtts(UDP_packets, ICMP_packets, src_dest_packets, src_dest_packets, True)
    return

#helper for get_rtts
def print_RTT(src_ip, intermediade_routers, rtts):
    ave_rtts = []
    for router in intermediade_routers:
        ip = router.IP_header.src_ip
        ave_rtt = 0
        count = 0
        cur_rtts = []
        for rtt in rtts:
            if(rtt[1] == ip):
                ave_rtt += rtt[0]
                count += 1
                cur_rtts.append(rtt[0])
        if(count > 0):
            ave_rtt = ave_rtt/count
            sd = 0
            for rtt in cur_rtts:
                rtt = rtt - ave_rtt
                sd += (rtt*rtt)
            if endian == "<":
                sd = round(math.sqrt(sd/count)*1000, 6)
                ave_rtt *= 1000
            else:
                sd = round(math.sqrt(sd/count), 6)
            ave_rtts.append((ip, round(ave_rtt, 6), sd))

    for ave_rtt in ave_rtts:
        print("The average RTT between ", src_ip, " and ", ave_rtt[0], " is: ", ave_rtt[1], " ms, the s.d. is: ", ave_rtt[2], " ms")
    return
        
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: Incorrect argument number. Check README.txt")
        exit(0)
    main(sys.argv[1])