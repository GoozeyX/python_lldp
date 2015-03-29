import socket
import struct
import binascii

ETH_P_ALL = 0x0003
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
rawSocket.bind(("eth0", ETH_P_ALL))

while True:
    packet = rawSocket.recvfrom(65565)
    packet = packet[0]
    lldpPayload = packet[14:]
    ethernetHeaderTotal = packet[0:14]

    ethernetHeaderUnpacked = struct.unpack("!6s6s2s",ethernetHeaderTotal)
    ethernetHeaderProtocol = ethernetHeaderUnpacked[2]

    if ethernetHeaderProtocol != '\x88\xCC':
        continue

    lldp_tlv_header = struct.unpack("!H", lldpPayload[:2])
    print lldp_tlv_header
    print binascii.hexlify(lldp_tlv_header)

    print "****************_ETHERNET_FRAME_****************"
    print "Type:            ", binascii.hexlify(ethernetHeaderProtocol)
    print "************************************************"

# from: https://github.com/openstack/ironic-python-agent/blob/master/ironic_python_agent/netutils.py
# tlvhdr = struct.unpack('!H', buff[:2])[0]
# tlvtype = (tlvhdr & 0xfe00) >> 9
# tlvlen = (tlvhdr & 0x01ff)
# tlvdata = buff[2:tlvlen + 2]
# buff = buff[tlvlen + 2:]
# lldp_info.append((tlvtype, tlvdata))
# return lldp_info