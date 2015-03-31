

#!/usr/bin/env python
import struct
import sys,os
import socket
import binascii

rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
#ifconfig eth0 promisc up
receivedPacket=rawSocket.recv(2048)

#Ethernet Header...
ethernetHeader=receivedPacket[0:14]
ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
destinationIP= binascii.hexlify(ethrheader[0])
sourceIP= binascii.hexlify(ethrheader[1])
protocol= binascii.hexlify(ethrheader[2])

print "Destination: " + destinationIP
print "Source: " + sourceIP
print "Protocol: "+ protocol

#IP Header... 
ipHeader=receivedPacket[14:34]
ipHdr=struct.unpack("!12s4s4s",ipHeader)
destinationIP=socket.inet_ntoa(ipHdr[2])
sourceIP=socket.inet_ntoa(ipHdr[1])
print "Source IP: " +sourceIP
print "Destination IP: "+destinationIP

#TCP Header...
tcpHeader=receivedPacket[34:54]
tcpHdr=struct.unpack("!2s2s16s",tcpHeader)
sourcePort=socket.inet_ntoa(tcpHdr[0])
destinationPort=socket.inet_ntoa(tcpHdr[1])
print "Source Port: " + sourcePort
print "Destination Port: " + destinationPort

