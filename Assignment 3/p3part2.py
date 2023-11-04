from ipaddress import IPv4Address
from sqlite3 import connect
from packet_struct import *
from struct import *
import sys
import math
import threading

def main(filenames):
    #sys.stdout = open("Output.txt", "w")
    file_data = []
    for filename in filenames:
        cap_file = open(filename, "rb")
        global endian
        endian = '<'

        glob = cap_file.read(24)

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
        cur_pack = packet()
        cur_pack.timestamp_set(cap_time_sec, cap_time_msec, 0, endian)
        orig_time = cur_pack.timestamp

        while(len(packet_head) > 15):
            pack_num += 1
            cap_time_sec = packet_head[0:4]
            cap_time_msec = packet_head[4:8]
            
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
                else:#(cur_ICMP_header.type == 11 or cur_ICMP_header.type == 3):
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
                if cur_pack.IP_header.frag_offset == 0:
                    if cur_UDP_header.dst_port < 33434 or cur_UDP_header.dst_port > 33529:
                        packet_head = cap_file.read(16)
                        continue
                cur_pack.UDP_header = cur_UDP_header
                UDP_packets.append(cur_pack)

            packet_head = cap_file.read(16)

        if windows:
            file_data.append(list_addresses_win(ICMP_packets, ICMP_echo_packets))
        else:
            file_data.append(list_addresses(ICMP_packets, UDP_packets))
    check_intermediate_routers(file_data)

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
    return (cur_IP_header.ip_header_len, cur_IP_header.protocol)

#checks if intermediade_routers are the same accross trace files and prints wither RTTS or difference in intermediate routers
def check_intermediate_routers(data):
    max_len = 0
    for router_list in data:
        if len(router_list[2]) > max_len:
            max_len = len(router_list[2])

    router_matrix = [["_"+" "*15 for i in range(0,max_len)] for j in range(0, len(data))]
    inner_index = 0
    outer_index = 0
    padding_length = 0
    for router_data in data:
        I_routers = router_data[2]
        inner_index = 0
        for cur_router in I_routers:
            router_matrix[outer_index][inner_index] = cur_router.IP_header.src_ip
            if len(router_matrix[outer_index][inner_index]) < 16:
                padding_length = 16 - len(router_matrix[outer_index][inner_index])
            router_matrix[outer_index][inner_index] += padding_length*" "
            inner_index += 1
        outer_index += 1
    
    rtts = []
    rtt_data = []
    #get rtts
    for trace_data in data:
        if trace_data[3]:
            rtt_data = get_rtts_win(trace_data[0], trace_data[1], trace_data[2], trace_data[4])
            rtts.append(print_RTT(rtt_data[1], rtt_data[0], trace_data[4]))
        else:
            rtt_data = get_rtts(trace_data[0], trace_data[1], trace_data[2], trace_data[4])
            rtts.append(print_RTT(rtt_data[1], rtt_data[0], trace_data[4]))

    highest_ttl = 0
    for rtt_list in rtts:
        for rtt in rtt_list:
            if rtt[1] > highest_ttl:
                highest_ttl = rtt[1]
    
    #build probes matrix
    probes_matrix = [["_"+" "*18 for i in range(0,highest_ttl)] for j in range(0,len(rtts))]
    inner_index = 0
    outer_index = 0
    padding_length = 0
    for rtt_list in rtts:
        inner_index = 0
        for rtt in rtt_list:
            probes_matrix[outer_index][inner_index] = str(rtt[2])
            if len(probes_matrix[outer_index][inner_index]) < 11:
                padding_length = 11 - len(probes_matrix[outer_index][inner_index])
            probes_matrix[outer_index][inner_index] += padding_length*" " + " "*8
            inner_index += 1
        outer_index += 1
    
    #print probes
    print("\033[1;31mPrinting probe data.\n\033[1;36m")
    initial_padding = "            "
    print("\033[1;36mTTL" , " ", "Probes in trace 1", " ","Probes in trace 2", " ","Probes in trace 3", " ","Probes in trace 4", " ","Probes in trace 5","\033[0;37m")
    for i in range(0, highest_ttl):
        #used to adjust padding
        if i == 9:
            initial_padding = "           "
        if i == 99:
            initial_padding = "          "
        #assuming each ttl is incremented by one
        print((i+1), initial_padding, probes_matrix[0][i], probes_matrix[1][i], probes_matrix[2][i], probes_matrix[3][i], probes_matrix[4][i])
    print("\033[1;31mEnd of probe data.\n\033[1;36m")
    


    equal_router_list = compare_intermediate_routers(router_matrix)
    if not equal_router_list:
        print("\033[1;31mIntermediate routers differ!\n\033[1;36m")
        #printing the matrix
        initial_padding = "  "
        print("\033[1;36m", " "*27, "tracefile1", " "*5,"tracefile2", " "*5,"tracefile3", " "*5,"tracefile4", " "*5,"tracefile5", " "*5,"\033[0;37m")
        for i in range(0, max_len):
            if i == 9:
                initial_padding = " "
            if i == 99:
                initial_padding = ""
            print("\033[1;36mIntermediate Router: ", i+1, "\033[0;37m", initial_padding, router_matrix[0][i], router_matrix[1][i], router_matrix[2][i], router_matrix[3][i], router_matrix[4][i])
        print("")
        print("- From the table above you can see the intermediade_routers list is not the same.")
        print("- This could be due to the hosts of each traceroute being located in different regions, or The shortest paths are different \n  between the different intermediade routers.")
        print("- Considering some ttls may be the same some packets may go to the incorrect intermediate router for the given destination.")
    else:
        print("\033[1;31mIntermediate routers are the same, calculating RTTs.\n\033[1;36m")
        rtts_matrix = [["_"+" "*11 for i in range(0,highest_ttl)] for j in range(0,len(rtts))]
        inner_index = 0
        outer_index = 0
        padding_length = 0
        for rtt_list in rtts:
            inner_index = 0
            for rtt in rtt_list:
                rtts_matrix[outer_index][inner_index] = str(rtt[0])
                if len(rtts_matrix[outer_index][inner_index]) < 11:
                    padding_length = 11 - len(rtts_matrix[outer_index][inner_index])
                rtts_matrix[outer_index][inner_index] += padding_length*" " + " "*13
                inner_index += 1
            outer_index += 1

        ave_rtt_per_hop = []
        ave_rtt = 0
        max_rtt = 0
        max_ttl = 0
        for i in range(0, highest_ttl):
            for j in range(0, len(rtts)):
                ave_rtt += rtts[j][i][0]
            ave_rtt = round(ave_rtt/len(rtts), 6)
            ave_rtt_per_hop.append(ave_rtt)
            if ave_rtt > max_rtt:
                max_rtt = ave_rtt
                max_ttl = rtts[j][i][1] - 1 #to correct indexing since ttl start at 1 index start at 0
        
        for i in range(0, len(ave_rtt_per_hop)):
            if i == max_ttl:
                ave_rtt_per_hop[i] = "\033[4;31m" + str(ave_rtt_per_hop[i]) + "\033[0;37m"
            else:    
                ave_rtt_per_hop[i] = "\033[0;31m" + str(ave_rtt_per_hop[i]) + "\033[0;37m"


        initial_padding = "         "
        print("\033[1;36m", "TTL" , " ", "Average RTT in trace 1", " ","Average RTT in trace 2", " ","Average RTT in trace 3", " ","Average RTT in trace 4", " ","Average RTT in trace 5", "  Average RTT over traces","\033[0;37m")
        for i in range(0, len(rtts_matrix[0])):
            #underline if max
            if i == max_ttl:
                ttl = "\033[4;36m " + str(i+1) + "\033[0;37m"
            else:
                ttl = "\033[1;36m " + str(i+1) + "\033[0;37m"
            #used to adjust padding
            if i == 9:
                initial_padding = "        "
            if i == 99:
                initial_padding = "       "
            #assuming each ttl is incremented by one
            print(ttl, initial_padding, rtts_matrix[0][i], rtts_matrix[1][i], rtts_matrix[2][i], rtts_matrix[3][i], rtts_matrix[4][i], ave_rtt_per_hop[i])
        
        print("")
        print("- Over all the trace files, hop: ", str(max_ttl+1), " has the longest average RTT.")
        print("- This hop will most likely take the most time since on average out of all the hops it took the most time.")
        print("- This could be due to little bandwidth on the network, or that the hop involved visiting multiple routers")

#helper for check_intermediate_routers
#compares based on first entry
def compare_intermediate_routers(router_matrix):
    equal = True
    for i in range(0, len(router_matrix[0])):
        j = 0
        for j in range(0, len(router_matrix)):
            if(router_matrix[0][i] != router_matrix[j][i]):
                router_matrix[j][i] = "\033[2;" + str(j + 30) + "m" + router_matrix[j][i] + "\033[0;37m"
                equal = False
            j += 1
    return equal

#Gets intermediade_routers for windows trace files then calls get_rtts_win
def list_addresses_win(ICMP_packets, ICMP_echo_packets):
    intermediade_routers = []
    dest_ip = ICMP_packets[0].ICMP_header.dst_ip
    src_dest_packets = []

    for packet in ICMP_packets:
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
    return (ICMP_echo_packets, ICMP_packets, intermediade_routers, True, src_dest_packets)

#Gets intermediade_routers for linux trace files then calls get_rtts
def list_addresses(ICMP_packets, UDP_packets):
    intermediade_routers = []
    src_dest_packets = []
    dest_ip = ICMP_packets[0].ICMP_header.dst_ip

    for packet in ICMP_packets:
        cur_src_port = packet.ICMP_header.UDP_src_port
        probe_count = 0
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
    intermediade_routers.sort(key=lambda x: x.hop_count)
    return (UDP_packets, ICMP_packets, intermediade_routers, False, src_dest_packets)

#gets the RTTS for a windows tracefile (including host to destination)
def get_rtts_win(ICMP_echo_packets, ICMP_packets, intermediade_routers, src_dest_packets, flag=False):
    rtts = []
    icmp_data = []

    for echo_packet in ICMP_echo_packets:
        seq_num = echo_packet.ICMP_header.echo_seq_num
        for icmp_packet in ICMP_packets:
            if(seq_num == icmp_packet.ICMP_header.echo_seq_num):
                icmp_data.append((echo_packet, icmp_packet))
                rtts.append((icmp_packet.timestamp-echo_packet.timestamp, icmp_packet.IP_header.src_ip, echo_packet.hop_count))

    frag_id = -1
    for echo_packet in ICMP_echo_packets:
        if echo_packet.IP_header.flags == 0x20 and echo_packet.IP_header.frag_offset == 0:
            frag_id = echo_packet.IP_header.identification
        if frag_id == echo_packet.IP_header.identification:
            #find corresponding entry in rtts
            for other_packet in icmp_data:
                if other_packet[0].IP_header.identification == frag_id:
                    rtts.append((other_packet[1].timestamp - echo_packet.timestamp, other_packet[1].IP_header.src_ip, echo_packet.hop_count))
                    break
    
    if not flag:
        rtts.append(get_rtts_win(ICMP_echo_packets, ICMP_packets, src_dest_packets, src_dest_packets, True))
        return (rtts, intermediade_routers)
    return rtts

#gets the RTTS for a linux tracefile (including host to destination)
def get_rtts(UDP_packets, ICMP_packets, intermediade_routers, src_dest_packets, flag=False):
    rtts = []
    udp_icmp_data = []
    for udp_packet in UDP_packets:
        src_port = udp_packet.UDP_header.src_port
        for icmp_packet in ICMP_packets:
            if(src_port == icmp_packet.ICMP_header.UDP_src_port):
                udp_icmp_data.append((udp_packet, icmp_packet))
                rtts.append((icmp_packet.timestamp-udp_packet.timestamp, icmp_packet.IP_header.src_ip, icmp_packet.hop_count))
    
    frag_id = -1
    for udp_packet in UDP_packets:
        if udp_packet.IP_header.flags == 0x20 and udp_packet.IP_header.frag_offset == 0:
            frag_id = udp_packet.IP_header.identification
        if frag_id == udp_packet.IP_header.identification:
            #find corresponding entry in rtts
            for other_packet in udp_icmp_data:
                if other_packet[0].IP_header.identification == frag_id:
                    rtts.append((other_packet[1].timestamp - udp_packet.timestamp, other_packet[1].IP_header.src_ip, other_packet.hop_count))
                    break

    if not flag:
        rtts.append(get_rtts(UDP_packets, ICMP_packets, src_dest_packets, src_dest_packets, True))
        return (rtts, intermediade_routers)
    return rtts

#helper for get_rtts
def print_RTT(intermediade_routers, rtts, src_dest_packets):
    ave_rtts = []
    prev_ttl = -1
    for router in intermediade_routers:
        ttl = router.hop_count
        if prev_ttl == ttl:
            continue
        router_with_cur_ttl = []
        for other_router in intermediade_routers:
            if other_router.hop_count == ttl:
                router_with_cur_ttl.append(other_router)
        ave_rtt = 0
        count = 0
        for other_router in router_with_cur_ttl:
            ip = other_router.IP_header.src_ip
            for rtt in rtts:
                if(rtt[1] == ip):
                    ave_rtt += rtt[0]
                    count += 1 
        if(count > 0):
            ave_rtt = ave_rtt/count
            if endian == "<":
                ave_rtts.append((round(ave_rtt*1000, 6), ttl, count))
            else:
                ave_rtts.append((round(ave_rtt, 6), ttl, count))
        prev_ttl = ttl
    return ave_rtts
        
if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Error: Incorrect argument number. Check README.txt")
        exit(0)
    main(sys.argv[1:6])