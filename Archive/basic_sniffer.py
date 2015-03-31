import socket


# my stuff to read: http://www.kanadas.com/program-e/2014/08/raw_socket_communication_on_li.html
#https://askldjd.wordpress.com/2014/01/15/a-reasonably-fast-python-ip-sniffer/
#create an INET, raw socket
rawSocket = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.IPPROTO_TCP)
#find network interfaces and devices, if os linux|aix|solaris

 
# receive a packet
while True:
    # socket.recv(bufsize[, flags])
    print s.recvfrom(65565)
    packet = s.recvfrom(65565)
    #this is because the packets sniffed/received look like this:
    #('E \x00(\xcc\xff\x00\x000\x06jrJ}G\x13\xc0\xa8\x01\x06\x01\xbb\xa3\xdc\x0b\xbeJ0\x1aFbtP******', ('74.125.71.19', 0))
    packet = packet[0]


# #http://www.security.securethelock.com/packet-headers/
# http://stackoverflow.com/questions/17602455/raw-socket-python-packet-sniffer
# http://stackoverflow.com/questions/24415294/python-arp-sniffing-raw-socket-no-reply-packets
    #Ethernet Header
ethernetHeader = pkt[0][0:14]
eth_hdr = struct.unpack("!6s6s2s", ethernetHeader)
destination= binascii.hexlify(eth_hdr[0])
source= binascii.hexlify(eth_hdr[1])
protocol= binascii.hexlify(eth_hdr[2])
print "Destination: " +destination
print "Source: " +source
print "Protocol:" +protocol