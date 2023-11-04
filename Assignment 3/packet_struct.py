import struct
from typing import Protocol

endian = "<"

#Provided for the assignemnt

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    #Added new vars
    ttl = None
    Protocol = None
    identification = 0
    flags = 0
    frag_offset = 0
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
        self.ttl = None
        self.identification = 0
        self.flags = 0
        self.frag_offset = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length

    def ttl_set(self, ttl):
        self.ttl = ttl
    
    def protocol_set(self, protocol):
        self.protocol = protocol

    def set_identification(self, identification):
        self.identification = identification

    def set_flags(self, flags):
        self.flags = flags

    def set_frag_offset(self, offset):
        self.frag_offset = offset
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
    
    def get_ttl(self, buffer):
        self.ttl_set((buffer[0])&0xFF)

    def get_protocol(self, buffer):
        protocol = buffer
        self.protocol_set(protocol)

    def get_identification(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        identification = num1 + num2 + num3 + num4
        self.set_identification(identification)

    def get_flags_offset(self, buffer):
        flag = buffer[0] & 0x20 #only care about fragment flag
        num1 = (buffer[0] & 31) << 3
        num2 = (buffer[1])
        offset = (num1+num2)*8
        self.set_flags(flag)
        self.set_frag_offset(offset)


class ICMP_Header:
    UDP_src_port = 0
    UDP_dst_port = 0
    echo_seq_num = 0
    src_ip = 0
    dst_ip = 0
    type = 0

    def __init__(self):
        self.UDP_src_port = 0
        self.type = 0
        self.echo_seq_num = 0
        self.src_ip = 0
        self.dst_ip = 0

    def get_echo_seq_num(self, buffer):
        #echo_seq_num = struct.unpack('BB', buffer)
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.echo_seq_num = num1+num2+num3+num4
    
    def get_type(self, buffer):
        type = struct.unpack('B', buffer)
        self.type = type[0] 

    def get_UDP_src_port(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.UDP_src_port = num1+num2+num3+num4

    def get_UDP_dst_port(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.UDP_dst_port = num1+num2+num3+num4

    def get_IP(self, buffer, buffer1):
        src_addr = struct.unpack('BBBB',buffer)
        dst_addr = struct.unpack('BBBB',buffer1)
        self.src_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        self.dst_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])

class UDP_Header:
    src_port = 0
    dst_port = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0

    def get_src_port(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.src_port = num1+num2+num3+num4

    def get_dst_port(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.dst_port = num1+num2+num3+num4
    
class packet():
    
    #pcap_hd_info = None
    IP_header = None
    UDP_header = None
    ICMP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    hop_count = 0
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.UDP_header = UDP_Header()
        self.ICMP_header = ICMP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.hop_count = 0
        
    def timestamp_set(self,buffer1,buffer2,orig_time, endian):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        if endian == "<":
            self.timestamp = round(((seconds)+(microseconds*0.000000001))-orig_time,6)
        else:
            self.timestamp = round(((seconds)+(microseconds*0.000001))-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)

    def set_endian(endian):
        endian = endian
