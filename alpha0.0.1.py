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
    #[0] at the end of the unpack is because of the tuple returnvalue
    # !H unpacks as an unsigned short, which has a size of two bytes, which is what we need because the TLV "header" is 9 and 7 bits long (2bytes)
    tlv_header = struct.unpack("!H", lldpPayload[:2])[0]
    tlv_type = tlv_header >> 9 #this shifts away the length part of the TLV leaving us with just the type
    tlv_len = (tlv_header & 0x01ff)
    tlv_payload = lldpPayload[2:tlv_len]
    tlv_subtype = struct.unpack("!B", tlv_payload[0:1]) #tlv_payload in this case is 3 & 4 byte of the tlv structure
    tlv_datafield = tlv_payload[1:tlv_len]
    print "now printing tlv_subtype: \n"
    print tlv_subtype
    # if tlv_type == 0x7f:
    #     _tlv_oui = unpack("!BBB", tlv_payload[:3])
    #     tlv_subtype = unpack("!B", tlv_payload[3:3 + 1])[0]
    #     tlv_payload = tlv_payload[3 + 1:]
    # print tlv_header
    print "Now printing TLV Type: "
    print tlv_type
    print "Now printing TLV Payload: "
    print tlv_payload[1:tlv_len] # this is because we already moved the beginning when we set the payload
    print "\nnow printing hexlify on tlv_payload:\n"
    print binascii.hexlify(tlv_payload[1:tlv_len])
    print "Now Printing tlv len: \n"
    print tlv_len

    print "Printing tlv_datafield:\n"
    print tlv_datafield
    print binascii.hexlify(tlv_datafield)
    # print tlv_type
    # print tlv_subtype
    # print tlv_payload


    # print lldp_tlv_header
    # print binascii.hexlify(lldp_tlv_header)

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

# # LLDP Length:
# LLDP_TLV_TYPE_BIT_LEN = 7
# LLDP_TLV_LEN_BIT_LEN = 9
# LLDP_TLV_HEADER_LEN = 2         # 7 + 9 = 16
# LLDP_TLV_OUI_LEN = 3
# LLDP_TLV_SUBTYPE_LEN = 1
# # LLDP Protocol BitFiddling Mask:
# LLDP_TLV_TYPE_MASK = 0xfe00
# LLDP_TLV_LEN_MASK = 0x1ff
# # LLDP Protocol ID:
# LLDP_PROTO_ID = 0x88cc
# # LLDP TLV Type:
# LLDP_TLV_TYPE_CHASSISID = 0x01
# LLDP_TLV_TYPE_PORTID = 0x02
# LLDP_TLV_DEVICE_NAME = 0x05
# LLDP_PDUEND = 0x00
# LLDP_TLV_ORGANIZATIONALLY_SPECIFIC = 0x7f
# # LLDP TLV OUI Type:
# LLDP_TLV_OUI_802_1 = 0x0008c2
# LLDP_TLV_OUI_802_3 = 0x00120f

# ## Magic string for unpack packet:
# UNPACK_ETH_HEADER_DEST = '!%s' % ('B' * ETH_ALEN)
# UNPACK_ETH_HEADER_SRC = '!%s' % ('B' * ETH_ALEN)
# UNPACK_ETH_HEADER_PROTO = '!H'

# ## Magic string for unpack LLDP packet:
# UNPACK_LLDP_TLV_TYPE = '!H'
# UNPACK_LLDP_TLV_OUI = '!%s' % ('B' * LLDP_TLV_OUI_LEN)
# UNPACK_LLDP_TLV_SUBTYPE = '!B'