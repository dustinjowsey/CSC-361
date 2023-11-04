from ipaddress import IPv4Address
from sqlite3 import connect
from packet_struct import *
from struct import *
import sys
import threading

def main(filename):
    capFile = open(filename, "rb")
    
    endian = '<'

    glob = capFile.read(24)

    #check endianess
    magicNum = glob[0:4]
    if magicNum == 0xa1b2c3d4:
        endian = '>'
    incLengthReadFormat = endian + "I"

    packetNum = 0
    packetHead = capFile.read(16)
    packets = []
    origTime = 0

    while(len(packetHead) > 15):
        packetNum += 1
        capTimeSec = packetHead[0:4]
        capTimeMsec = packetHead[4:8]
        
        incLength = unpack(incLengthReadFormat, packetHead[8:12])
        packetData = capFile.read(incLength[0])
        #Packet header info
        curPacket = packet()
        curPacket.packet_No_set(packetNum)
        if packetNum == 1:
            curPacket.timestamp_set(capTimeSec, capTimeMsec, 0.0)
            origTime = curPacket.timestamp
            curPacket.timestamp = 0
        curPacket.timestamp_set(capTimeSec, capTimeMsec, origTime)
        #ethernet header
        ethHeader = packetData[0:14]
        #IPv4 Header
        IPV4Header = packetData[14:34]
        curIPV4Header = IP_Header()
        curIPV4Header.get_header_len(IPV4Header[0:1])
        curIPV4Header.get_total_len(IPV4Header[2:4])
        protocol = IPV4Header[9]
        if(protocol != 6):
            continue
        curIPV4Header.get_IP(IPV4Header[12:16], IPV4Header[16:20])
        curPacket.IP_header = curIPV4Header
        #TCP Header
        TCPHeader = packetData[(14 + curIPV4Header.ip_header_len):(14 + curIPV4Header.ip_header_len + 20)]
        curTCPHeader = TCP_Header()
        curTCPHeader.get_src_port(TCPHeader[0:2])
        curTCPHeader.get_dst_port(TCPHeader[2:4])
        curTCPHeader.get_seq_num(TCPHeader[4:8])
        curTCPHeader.get_ack_num(TCPHeader[8:12])
        curTCPHeader.get_data_offset(TCPHeader[12:13])
        curTCPHeader.get_flags(TCPHeader[13:14])
        curTCPHeader.get_window_size(TCPHeader[14:15], TCPHeader[15:16])
        curPacket.TCP_header = curTCPHeader

        packets.append(curPacket)
        packetHead = capFile.read(16)

    connections = find_connections(packets)

    printConnections(connections)
    return

def find_connections(packets):
    connections = []
    connectionNum = 1
    lastPackFlag = 0
    prevPort = -1
    for packet in packets:
        #only add new connections
        if packet.TCP_header.flags["SYN"] == 1 and packet.TCP_header.flags["ACK"] == 0:
            connection = {
                "Connection" : connectionNum,
                "SrcAdd" : packet.IP_header.src_ip,
                "DestAdd" : packet.IP_header.dst_ip,
                "SrcPort" : packet.TCP_header.src_port,
                "DestPort" : packet.TCP_header.dst_port,
                "Status" : None,
                "Start time" : packet.timestamp,
                "End time" : None,
                "Duration" : None,
                "PackDestSrc" : 0,
                "PackSrcDest" : 0,
                "TotPack" : 0,
                "BytesSrcDest" : 0,
                "BytesDestSrc" : 0,
                "TotBytes" : 0,
                "CompleteConnection" : 0,
                "ResetCon" : 0,
                "OpenCon" : 0,
                "minWin" : -1,
                "maxWin" : -1,
                "meanWin" : 0.0,
                "RTT" : 0
            }
            #dont want to add the same connection twice (SYN flag on response from SYN)
            if packet.TCP_header.src_port == prevPort:
                continue
            prevPort = packet.TCP_header.src_port
            connection = getConnectionInfo(connection, packets)
            connections.append(connection)
            connectionNum += 1
    return connections

def getConnectionInfo(connection, packets):
    srcFlag = 0
    destFlag = 0
    resetFlag = 0
    synConnections = 0
    finConnections = 0
    t1 = 0
    t2 = 0
    for packet in packets:
        if packet.IP_header.src_ip == connection["SrcAdd"] and packet.TCP_header.src_port == connection["SrcPort"] and packet.IP_header.dst_ip == packet.IP_header.dst_ip == connection["DestAdd"] and packet.TCP_header.dst_port == connection["DestPort"]:
            srcFlag = 1
        if packet.IP_header.src_ip == connection["DestAdd"] and packet.TCP_header.src_port == connection["DestPort"] and packet.IP_header.dst_ip == connection["SrcAdd"] and packet.TCP_header.dst_port == connection["SrcPort"]:
            destFlag = 1
        if srcFlag == 1 or destFlag == 1:
            connection["TotBytes"] += (packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset)
            connection["TotPack"] += 1

            if connection["minWin"] > packet.TCP_header.window_size or connection["minWin"] == -1:
                connection["minWin"] = packet.TCP_header.window_size
            if connection["maxWin"] < packet.TCP_header.window_size or connection["maxWin"] == -1:
                connection["maxWin"] = packet.TCP_header.window_size
            connection["meanWin"] += packet.TCP_header.window_size
            
            if srcFlag == 1 and packet.TCP_header.flags["SYN"] == 1:
                t1 = packet.timestamp
            if destFlag == 1 and packet.TCP_header.flags["SYN"] == 1:
                t2 = packet.timestamp
                rtt = round(t2 - t1, 6)
                connection["RTT"] = rtt

            if packet.TCP_header.flags["RST"] == 1:
                resetFlag = 1
            if packet.TCP_header.flags["SYN"] == 1:
                synConnections += 1
            if packet.TCP_header.flags["FIN"] == 1:
                finConnections += 1
                if srcFlag == 1:
                    addSrcDest(connection, packet)
                else:
                    addDestSrc(connection, packet)
                connection["End time"] = packet.timestamp
                connection["Duration"] = round(connection["End time"] - connection["Start time"], 6)
            else:
                if srcFlag == 1:
                    addSrcDest(connection, packet)
                if destFlag == 1:
                    addDestSrc(connection, packet)
            srcFlag = 0
            destFlag = 0
        else:
            #Skip packets not in the current connection
            continue
    connection["Status"] = "S" + str(synConnections) + "F" + str(finConnections)
    if resetFlag == 1:
        connection["Status"] += "/R"
        connection["ResetCon"] = 1
    if synConnections > 0 and finConnections > 0:
        connection["CompleteConnection"] = 1
    if finConnections == 0:
        connection["OpenCon"] = 1
    return connection

#helper function to save writing these lines repeatedly
def addSrcDest(connection, packet):
    connection["PackSrcDest"] += 1
    connection["BytesSrcDest"] += packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset
#helper function to save writing these lines repeatedly
def addDestSrc(connection, packet):
    connection["PackDestSrc"] += 1
    connection["BytesDestSrc"] += packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset

def printConnections(connections):
    output = open("Output.txt", 'w')
    sys.stdout = output
    print("A) Total number of connections: ", len(connections), "\n" , "-"*40, "\nB) Connection's details\n")
    completeCon = 0
    resetCon = 0
    openCon = 0

    minDuration = -1
    meanDuration = 0
    maxDuration = -1

    minRTT = -1
    meanRTT = 0
    maxRTT = -1

    minPack = -1
    meanPack = 0
    maxPack = -1

    minWindow = -1
    meanWindow = 0
    maxWindow = -1
    compTotPack = 0
    for connection in connections:
        print("Connection ", connection["Connection"], ":")
        print("Source Address: ", connection["SrcAdd"])
        print("Destination Address: ", connection["DestAdd"])
        print("Source Port: ", connection["SrcPort"])
        print("Destination Port: ", connection["DestPort"])
        print("Status: ", connection["Status"])
        if connection["CompleteConnection"]:
            completeCon += 1
            
            if minDuration > float(connection["Duration"]) or minDuration == -1:
                minDuration = float(connection["Duration"])
            if maxDuration < float(connection["Duration"]) or maxDuration == -1:
                maxDuration = float(connection["Duration"])
            meanDuration += float(connection["Duration"])

            if minRTT > connection["RTT"] or minRTT == -1:
                minRTT = connection["RTT"]
            if maxRTT < connection["RTT"] or maxRTT == -1:
                maxRTT = connection["RTT"]
            meanRTT += connection["RTT"]

            if minPack > connection["TotPack"] or minPack == -1:
                minPack = connection["TotPack"]
            if maxPack < connection["TotPack"] or maxPack == -1:
                maxPack = connection["TotPack"]
            meanPack += connection["TotPack"]

            if minWindow > connection["minWin"] or minWindow == -1:
                minWindow = connection["minWin"]
            if maxWindow < connection["maxWin"] or maxWindow == -1:
                maxWindow = connection["maxWin"]
            meanWindow += connection["meanWin"]
            compTotPack += connection["TotPack"]

            print("Start Time: ", connection["Start time"])
            print("End Time: ", connection["End time"])
            print("Duration: ", connection["Duration"])
            print("Number of packets sent from Source to Destination: ", connection["PackSrcDest"])
            print("Number of packets sent from Destination to Source: ", connection["PackDestSrc"])
            print("Total number of packets: ", connection["TotPack"])
            print("Number of data bytes sent from Source to Destination: ", connection["BytesSrcDest"])
            print("Number of data bytes sent from Destination to Source: ", connection["BytesDestSrc"])
            print("Total number of data bytes: ", connection["TotBytes"])
            print("END")
        if connection["Connection"] != len(connections):
            print("+"*40)
        
        if connection["ResetCon"] == 1:
            resetCon += 1
        if connection["OpenCon"] == 1:
            openCon += 1

    meanDuration = round(meanDuration/completeCon, 6)
    meanPack = round(meanPack/completeCon, 6)
    meanWindow = round(meanWindow/compTotPack, 6)
    meanRTT = round(meanRTT/completeCon, 6)
    
    print("-"*40, "\nC) General\n\nTotal number of complete TCP connections: ", completeCon)
    print("Number of reset TCP connections: ", resetCon)
    print("Number of TCP connections that were still open when the trace capture ended: ", openCon)
    print("-"*40, "\nD) Complete TCP connections\n")
    print("Minimum time duration: ", minDuration, "seconds", "\nMean time duration: ", meanDuration,"\nMaximum time duration: ", maxDuration)
    print("\nMinimum RTT value: ", minRTT, " seconds", "\nMean RTT value: ", meanRTT, " seconds", "\nMaximum RTT value: ", maxRTT, " seconds")
    print("\nMinimum number of packets including send/recieved: ", minPack, "\nMean number of packets including both send/recieved: ", meanPack, "\nMaximum number of packets including both send/recieved: ", maxPack)
    print("\nMinimum recieve window size including both send/recieved: ", minWindow, " bytes")
    print("Mean recieve window size including both send/recieved: ", meanWindow, " bytes")
    print("Maximum recieve window size including both send/recieved: ", maxWindow, " bytes")
    print("-"*40)

if __name__ == "__main__":
    main(sys.argv[1])