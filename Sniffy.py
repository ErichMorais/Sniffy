#!/usr/bin/env python3
#=========================================================#
# [+] Title: Simple Network Sniffer                       #
# [+] Script: Sniffy.py                                   #
# [+] Blog: http://pytesting.blogspot.com                 #
#=========================================================#

import socket
import sys
import struct
import time
import sqlite3
from optparse import OptionParser

class ipv4(object):
    """ This class deals with the ip header level"""
    
    def __init__(self, header):
        self.header=header
    def extract(self):
        """ Extract IP Header elements """
        
        """ unpack header into:
            |_ B(Version+IHL)|B(TOS)|H(TotalLength)|H(ID)
            |_ H(Flags+FragmentOffset)|B(TTL)|B(Protocol)|H(CheckSum)
            |_ I(Source)|I(Destination)
            Note: "R" used to hold the reserved bits"""

        unpacked=struct.unpack("!BBHHHBBHII", self.header)
        header=[]
        # Version+IHL
        header+=unpackBit("4b4b", unpacked[0])
        # TOS: precedence, delay, throughput, reliability, monetary cost, Reserved
        header+=unpackBit("3b1b1b1b1b1b", unpacked[1])[:-1] # omit Reserved
        # total length
        header+=[unpacked[2]]
        # datagram id
        header+=[unpacked[3]]
        # flags(reserved, df, mf), fragment offset
        header+=unpackBit("1b1b1b13b", unpacked[4])[1:] # omit Reserved
        # Time to live in seconds
        header+=[unpacked[5]]
        # Next Protocol
        header+=[unpacked[6]]
        # Header Checksum
        header+=[unpacked[7]]
        # Source IP Address
        source=struct.pack("!I", unpacked[8]) # Pack address in "\xNN\xNN\xNN\xNN" format
        source=socket.inet_ntoa(source)
        header+=[source]
        # Destination IP Address
        destination=struct.pack("!I", unpacked[9])
        destination=socket.inet_ntoa(destination)
        header+=[destination]
        return header
    
    def parse(self):
        header=self.extract()
        try:
            db=sqlite3.connect("ip.sqlite")
            print("----IP Header----")
            print("\tVersion: %d"%header[0])
            print("\tInternet Header Length: %d bytes"%(header[1]*4))
            print("\tType of Service:")
            querry=db.execute("SELECT description FROM precedence WHERE id=%d"%header[2])
            print("\t\tPrecedence: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM delay WHERE id=%d"%header[3])
            print("\t\tDelay: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM throughput WHERE id=%d"%header[4])
            print("\t\tThroughput: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM reliability WHERE id=%d"%header[5])
            print("\t\tReliability: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM monetary_cost WHERE id=%d"%header[6])
            print("\t\tMonetary Cost: "+querry.fetchone()[0])
            print("\tTotal Length: %d bytes"%(header[7]))
            print("\tIdentification: "+hex(header[8])+ " (%d)"%(header[8]))
            print("\tFlags:")
            querry=db.execute("SELECT description FROM fragmentation WHERE id=%d"%header[9])
            print("\t\tFragmentation: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM more_fragments WHERE id=%d"%header[10])
            print("\t\tMore Fragments?: "+querry.fetchone()[0])
            print("\tFragment Offset: "+hex(header[11]))
            print("\tTime to Live: %d seconds"%header[12])
            querry=db.execute("SELECT description FROM protocol WHERE id=%d"%header[13])
            print("\tProtocol: "+querry.fetchone()[0])
            print("\tHeader Checksum: "+hex(header[14]))
            print("\tSource IP address: "+header[15])
            print("\tDestination IP address: "+header[16])
            db.close()
            return header[13] #nextp
        except:
            print("[-] Error: ip.sqlite database not found")

class ipv6(object):
    """ This class deals with the ip header level"""
    
    def __init__(self, header):
        self.header=header
    def extract(self):
        """ Extract IPv6 Header elements """
        
        unpacked=struct.unpack("!IHBB16s16s", self.header)
        header=[]
        # Version+Traffic Class + Flow Label
        header+=unpackBit("4b8b20b", unpacked[0]) 
        # Payload Length
        header+=[unpacked[1]]
        # Next Header
        header+=[unpacked[2]]
        # Hop Limit
        header+=[unpacked[3]]
        # IP Address
        ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, self.header[8:24])
        header+=[ipv6_src_ip]
        ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, self.header[24:40])
        header+=[ipv6_dst_ip]
        return header
    
    def parse(self):
        header=self.extract()
        try:
            db=sqlite3.connect("ip.sqlite")
            print("Version: %d"%header[0])    
            print("\tTraffic Class: %x"%header[1])
            print("\tFlow Label: %x"%header[2])
            print("\tPayload Length: %d"%header[3])
            querry=db.execute("SELECT description FROM protocol WHERE id=%d"%header[4])
            print("\tNext Header: "+querry.fetchone()[0])
            print("\tHop Limit: %d"%header[5])
            print("\tAddress: %s"%header[6])
            print("\tAddress: %s"%header[7])
            db.close()
            return header[4] #nextp
        except:
            print("[-] Error: ip.sqlite database not found") 

def nextHeader(nextp):
    try:
        db=sqlite3.connect("ip.sqlite")
        querry=db.execute("SELECT description FROM protocol WHERE id=%d"%header[4])
        nextp = querry.fetchone([0])  
        db.close()
        return nextp
    except:
        print("[-] Error: ip.sqlite database not found") 

def hopHeader(newPacket):
    packet = struct.unpack("!2b", newPacket[0:2])
    next_header = packet[0]
    hdr_ext_len = packet[1]

    print ("----HOP-BY-HOP----")
    print ("\tNext Header: %s" % nextHeader(next_header))
    print ("\tHeader Extension Length: %s" % (hdr_ext_len*8 + 8))

    newPacket = newPacket[int(hdr_ext_len*8 + 8):]
    return newPacket, next_header

def destinationHeader(newPacket):
    packet = struct.unpack("!2b", newPacket[0:2])
    next_header = packet[0]
    hdr_ext_len = packet[1]

    print ("----DESTINATION OPTIONS HEADER----")
    print ("\tNext Header: %s" % nextHeader(next_header))
    print ("\tHeader Extension Length: %s" % (hdr_ext_len*8 + 8))

    newPacket = newPacket[int(hdr_ext_len*8 + 8):]
    return newPacket, next_header

def routingHeader(newPacket):
    packet = struct.unpack("!4B", newPacket[0:4])
    next_header = packet[0]
    hdr_ext_len = packet[1]
    routing_type = packet[2]
    seg_left = packet[3]

    print ("----ROUTING HEADER----")
    print ("\tNext Header: %s" % nextHeader(next_header))
    print ("\tHeader Extension Length: %s" % (hdr_ext_len))
    print ("\tRouting Type: %s" % (routing_type))
    print ("\tSegments Left: %s" % (seg_left))

    newPacket = newPacket[int(hdr_ext_len*8 + 8):]
    return newPacket, next_header

def fragmentHeader(newPacket):
    packet = struct.unpack("!2B1H1I", newPacket[0:8])
    next_header = packet[0]
    reserved = packet[1]
    frag_offset = packet[2] >> 3
    identification = packet[3]

    print ("----FRAGMENT HEADER----")
    print ("\tNext Header: %s" % nextHeader(next_header))
    print ("\tReserved: %s" % (reserved))
    print ("\tFragment Offset: %s" % (frag_offset))
    print ("\tIdentification: %s" % (identification))

    newPacket = newPacket[8:]
    return newPacket, next_header

def authenticationHeader(newPacket):
    packet = struct.unpack("!2b", newPacket[0:2])
    next_header = packet[0]
    payload_len = packet[1]

    print ("----AUTHENTICATION HEADER----")
    print ("\tNext Header: %s" % nextHeader(next_header))
    print ("\tHeader Extension Length: %s" % (payload_len*4 + 8))

    newPacket = newPacket[int(payload_len*4 + 8):]
    return newPacket, next_header
            
def ICMP(newPacket):

	packet = struct.unpack("!BBH",newPacket[:4])
	print ("----ICMP HEADER----")
	print ("\tType: "+ str(packet[0]))
	print ("\tCode: "+ str(packet[1]))
	print ("\tCheckSum: "+ str(packet[2]))

	packet = newPacket [4:]
	return packet

def ICMPv6(newPacket):

	packet = struct.unpack("!BBH",newPacket[:4])
	print ("----ICMPv6 HEADER----")
	print ("\tType: "+ str(packet[0]))
	print ("\tCode: "+ str(packet[1]))
	print ("\tCheckSum: "+ str(packet[2]))

	packet = newPacket [4:]
	return packet

def UDPHeader(newPacket):
  packet = struct.unpack("!4H",newPacket[:8])
  print ("----UDP HEADER----")
  print ("\tSource Port: "+str(packet[0]))
  print ("\tDestination Port: "+str(packet[1]))
  print ("\tLenght: "+str(packet[2]))
  print ("\tChecksum: "+str(packet[3]))
  
  packet = newPacket[8:]
  return packet

def TCPHeader(newPacket):
   packet = struct.unpack("!2H2I4H",newPacket[0:20])
   print ("----TCP HEADER----")
   print ("\tSource Port: "+str(packet[0]))
   print ("\tDestination Port: "+str(packet[1]))
   print ("\tSequence Number: "+str(packet[2]))
   print ("\tAck. Number: "+str(packet[3]))
   print ("\tData Offset: "+str(packet[4] >> 12))
   print ("\tReserved: "+str((packet[4] >> 6) & 0x003F))
   tcpFlags = packet[4] & 0x003F
   print ("\tTCP Flags: "+str(tcpFlags))
   urgFlag = tcpFlags & 0x0020  #1111 1111 1111 1111 & 0000 0000 0010 0000
   if(urgFlag == 32):
     print ("\tUrgent Flag: Set")
   ackFlag = tcpFlags & 0x0010
   if(ackFlag == 16):
     print ("\tAck Flag: Set")
   pushFlag = tcpFlags & 0x0008
   if(pushFlag == 8):
     print ("\tPush Flag: Set")
   resetFlag = tcpFlags & 0x0004
   if(resetFlag == 4):
     print ("\tReset Flag: Set")
   synFlag = tcpFlags & 0x0002 
   if(synFlag == 2):
     print ("\tSyn Flag: Set")
   finFlag = tcpFlags & 0x0001  
   if(finFlag == True):
     print ("\tFin Flag: Set")

   print ("\tWindow: "+str(packet[5]))
   print ("\tChecksum: "+str(packet[6]))
   print ("\tUrgent Pointer: "+str(packet[7]))

   packet = newPacket[20:]
   return packet
   
def asciiDump(data):
    print("  ", end="")
    for x in data:
        if x in range(32,127):
            print(chr(x), end="")
        else:
            print(".", end="")
    print() # new line
            
def dump(data):
    print("--- DATA DUMP ---")
    print("Offset(h)  ", end="")
    for i in range(16):
        print("%02X "%i, end="")
    print("\tASCII")
    line=0 # every line holds 16 bytes
    index=0 # index of the current line in data
    for i in range(len(data)):
        if i%16==0:
            asciiDump(data[index:i])
            index=i
            # print the new line address
            print("%08X   "%line, end="")
            line+=1
        print("%02X "%data[i], end="")

    # Padding
    i+=1
    while i%16:
        print("   ", end="")
        i+=1
    # Last line ASCII dump
    asciiDump(data[index:])
    print("--- END DUMP  ---")
    print("********************************************************************")
    
def unpackBit(fmt, data):
    """ unpack data at the bit level """
    try:
        # strip "b" separated string into list
        elements=fmt.split("b")
        # get rid of the empty string added by split
        elements=elements[:-1]
        # str to int
        for i in range(len(elements)): 
            elements[i]=int(elements[i])
        # length in bits
        length=sum(elements, 0)
        # convert data to a binary string 
        binary=bin(data)
        # omit '0b' prefix
        binary=binary[2:]
        # paddings
        if length>len(binary):
            binary='0'*(length-len(binary))+binary
        if length!=len(binary):
            raise ValueError("Unmatched size of data")
    except ValueError as err:
        print("[-] Error: %s"%str(err))
        sys.exit(1)

    # List of unpacked Data
    uData=[] 
    for l in elements:
        # Convert the first l bits to decimal
        unpacked=int(binary[:l], 2)
        uData.append(unpacked)
        # git rid of the last unpacked data
        binary=binary[l:] 

    return uData

def sniff(packet):
	
    """ sniff a packet, parse it's header and dump the sniffed data """
    eHeader = struct.unpack("!H",packet[12:14]) 
    version = hex(eHeader[0])
    if version == '0x800': #ipv4
        ipheader=ipv4(packet[14:34]) # IP Header
        nextp = ipheader.parse()
        newpacket = packet[34:]
    elif version == '0x86dd': #ipv6
        ipheader=ipv6(packet[14:54]) # IP Header
        nextp = ipheader.parse()
        newpacket = packet[54:]
    else:
    	return 

    if (nextp == 0): #IPv6 Hop-by-Hop Option
        newpacket, nextp = hopHeader(newpacket)
    if (nextp == 60): #Destination Options for IPv6
        newpacket, nextp = destinationHeader(newpacket)
    if (nextp == 43): #IPv6 Routing header
        newpacket, nextp = routingHeader(newpacket)
    if (nextp == 44): #IPv6 Fragment header
        newpacket, nextp = fragmentHeader(newpacket)
    if (nextp == 51): #AH, Authentication Header
        newpacket, nextp = authenticationHeader(newpacket)
    # if (nextp == 50): #ESP, Encapsulating Security Payload
        # newpacket, nextp = encapsulingHeader(newpacket)
    if (nextp == 60): #Destination Options for IPv6
        newpacket, nextp = destinationHeader(newpacket)    

    
    if nextp == 6: # next protocol = TCP
        newpacket = TCPHeader(newpacket)
    elif nextp == 17: # next protocol = UDP
        newpacket = UDPHeader(newpacket)
    elif nextp == 1: # next protocol = ICMP
        newpacket = ICMP(newpacket)
    elif nextp == 58:
        newpacket = ICMPv6(newpacket)	
    dump(newpacket)	

def main():
    parser=OptionParser()
    parser.add_option("-n", dest="npackets", type="int",\
                      help="Number of packets to sniff")
    (options, args)=parser.parse_args()
    newPacket,nextProto = '',''
    #os.system('clear')
    packet = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
    try:
        if options.npackets!=None:
            for i in range(options.npackets):
                s = packet.recv(65356)
                sniff(s)
        else:
            while True:
                s = packet.recv(65356)
                sniff(s)
    except socket.error as err:
        print("[-] Error: %s"%str(err))
    except KeyboardInterrupt:
        print("[+] Keyboard Interruption captured: Existing")
       
if __name__=="__main__":
    main()


