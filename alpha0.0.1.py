import socket
import struct
import binascii

ETH_P_ALL = 0x0003
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
rawSocket.bind(("eth0", ETH_P_ALL))

while True:
    packet = rawSocket.recvfrom(65565)
    packet = packet[0]
    packetFramePayload = packet[14:]
    ethernetHeaderTotal = packet[0:14]

    ethernetHeaderUnpacked = struct.unpack("!6s6s2s",ethernetHeaderTotal)
    ethernetHeaderProtocol = ethernetHeaderUnpacked[2]

    if ethernetHeaderProtocol != '\x88\xCC':
        continue

    print "****************_ETHERNET_FRAME_****************"
    print "Type:            ", binascii.hexlify(ethernetHeaderProtocol)
    print "************************************************"
