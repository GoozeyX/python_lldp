import socket
import struct
import binascii

ETH_P_IP = 0x0003
sniff = socket.socket(socket.AF_PACKET,
                      socket.SOCK_RAW, # strip link layer header
                      socket.htons(ETH_P_IP))
sniff.bind(("wlan0", ETH_P_IP)) # ip packets from ethernet interface ("eth0")
# rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
# rawSocket.bind("192.168.0.16", "0x0003")
while True:
    packet = sniff.recvfrom(65565)
    #this is because the packets sniffed/received look like this:
    #('E \x00(\xcc\xff\x00\x000\x06jrJ}x01\xbb\xa3\xdc\x0b\xbeJ0\x1aFbtP******', ('xxx.xxx.xxx.xxx', 0))
    packet = packet[0]
    #Im choosing [0:14] because thats the first 14 bytes representing the dest mac address, source mac address and type
    ethernetHeaderTotal = packet[0:14]
    #Unpacking it into a tuple format
    ethernetHeaderUnpacked = struct.unpack("!6s6s2s",ethernetHeaderTotal)
    ethernetHeaderProtocol = ethernetHeaderUnpacked[2]

    #change this to '\x88\xCC' for lldp
    if ethernetHeaderProtocol == '\x86\xDD':
        print "Hooray HOORAY HOORAY HOORAY"

    print "****************_ETHERNET_FRAME_****************"
    print "Dest MAC:        ", 
    print "Source MAC:      ", 
    print "Type:            ", binascii.hexlify(ethernetHeaderProtocol)
    print "************************************************"
    # eth_protocol, eth_payload = unpack_ethernet_frame(packet)[3:]


# http://www.pythonforpentesting.com/2014/09/packet-injection-capturing-response.html