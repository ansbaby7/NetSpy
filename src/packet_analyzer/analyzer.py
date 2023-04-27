from struct import *
import sys
import socket

def get_mac(test):
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (test[0], test[1], test[2], test[3], test[4], test[5])
    return mac

def ethernet(raw,test):
    d,s,p = unpack('! 6s 6s H', raw[:14])
    dmactest = get_mac(test[0:6])
    smactest = get_mac(test[6:12])
    dmac = raw[0:6]
    smac = raw[6:12]
    proto = socket.htons(p)
    data = raw[14:]
    return dmactest,smactest,p,data

def get_ip(add):
    return '.'.join(map(str,add))

def ipv4(raw):
    versionl = raw[0]
    version = versionl>>4
    headerl = (versionl&15)*4
    ttl,proto,s,d = unpack('!8xBB2x4s4s',raw[:20])
    s = get_ip(s)
    d = get_ip(d)
    data = raw[headerl:]
    return version,headerl,ttl,proto,s,d,data

def tcpparser(raw):
    (sport,dport, seq,ack, offset_flags) = unpack('!HHLLH',raw[:14])
    offset = (offset_flags>>12)*4
    flag_urg = (offset_flags&32)>>5
    flag_ack = (offset_flags&16)>>4
    flag_psh = (offset_flags&8)>>3
    flag_rst = (offset_flags&4)>>2
    flag_syn = (offset_flags&2)>>1
    flag_fin = (offset_flags&1)
    data = raw[offset:]
    return sport,dport,seq,ack,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data

def udp_parser(raw):
    udp = unpack('!HHHH',raw)
    sport = udp[0]
    dport = udp[1]
    l = udp[2]
    checksum = udp[3]
    return sport,dport,l,checksum

s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
while True:
    test = s.recvfrom(65535)
    raw,add=test
    test = test[0]
    eth_length = 14
    eth_header = test[:eth_length]
    eth = ethernet(raw,test)
    print('\nEthernet Frame:')
    print('\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(eth[0],eth[1],socket.ntohs(eth[2])))
    if socket.ntohs(eth[2])==8:
        ip = ipv4(eth[3])
        ip_header = test[eth_length:20+eth_length]
        print('\tIPv4 Packet:')
        print('\t\t Version: {}, Header Lenght: {}, TTL: {}'.format(ip[0],ip[1],ip[2]))
        print('\t\t Protocol: {}, Source: {}, Destination: {}'.format(ip[3],ip[4],ip[5]))
        if ip[3]==6:
            tcp=tcpparser(ip[6])
            print('\tTCP Segment:')
            print('\t\tSource Port: {}, Destination Port: {}'.format(tcp[0],tcp[1]))
            print('\t\tSequence Number: {}, Acknowlegement: {}'.format(tcp[2],tcp[3]))
            print('\t\tFlags:')
            print('\t\t\tURG: {}, ACK: {}, PSH: {}'.format(tcp[4],tcp[5],tcp[6]))
            print('\t\t\tRST: {}, SYN: {}, FIN: {}'.format(tcp[7],tcp[8],tcp[9]))
            print('\t\tData:')
            bb = str(tcp[10])
            for i in range(0,len(bb),100):
                print('\t\t\t'+bb[i:i+100])
        if ip[3]==17:
            u  = ip[1]+eth_length
            udp_length = 8
            udp_header = test[u:u+8]
            udp = udp_parser(udp_header)
            print('\tUDP Segment:')
            print('\t\tSource Port {}, Destination Port {}'.format(udp[0],udp[1]))
            print('\t\tLength: {}, Checksum: {}'.format(udp[2],udp[3]))
            hsize = u + udp_length
            data = test[hsize:]
            print('\t\tData:')
            udp_data = str(data)
            for i in range(0,len(udp_data),100):
                print('\t\t\t'+udp_data[i:i+100])          