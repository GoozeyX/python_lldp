import socket
import struct
import binascii

ETH_P_ALL = 0x0003
rawSocket = socket.socket(17, socket.SOCK_RAW, socket.htons(0x0003))
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
    while lldpPayload:
    #[0] at the end of the unpack is because of the tuple returnvalue
    #!H unpacks as an unsigned short, which has a size of two bytes, which is what we need because the TLV "header" is 9 and 7 bits long (2bytes)
    #The right bitshift by 9 bits shifts away the length part of the TLV, leaving us with the TLV Type
    #The bitmask gives us the length of the real payload by masking the first 7 bits with a 0000000111111111 mask (0x01ff in hex)
    #tlv_TotalPayload is the 3rd-Nth byte of the TLV Frame
    #tlv_TotalPayload: we need to add +2 bytes because the address space changes when we cut off the header ( see http://standards.ieee.org/getieee802/download/802.1AB-2009.pdf page 24)
        tlv_header = struct.unpack("!H", lldpPayload[:2])[0]
        tlv_type = tlv_header >> 9
        tlv_len = (tlv_header & 0x01ff)
        tlv_TotalPayload = lldpPayload[2:tlv_len + 2]
        
        #if tlvtype is 4 then datafield must start at 0 because of the payload structure for Port Descriptions (see IEEE PDF)
        tlv_subtype = "" if tlv_type is 4 else struct.unpack("!B", tlv_TotalPayload[0:1])
        startbyte = 0 if tlv_type is 4 else 1
        #tlv_subtype = struct.unpack("!B", tlv_TotalPayload[0:1]) #tlv_TotalPayload in this case is 3 & 4 byte of the tlv structure (using !H because its a 2 byte size unsigned Short)

        tlv_datafield = tlv_TotalPayload[startbyte:tlv_len]

        #Data Gathering

        print "Now printing TLV Type: ",
        print tlv_type
        print "Now Printing tlv len in bytes: \n",
        print tlv_len
        print "now printing tlv_subtype: \n"
        # print tlv_subtype[0] (commenting this out because type 4 isnt a tuple)
        print "Now printing tlv_datafield: \n"
        print tlv_datafield #this is useless because its in binary.
        print "Printing tlv_datafield with binascii:\n"
        print binascii.hexlify(tlv_datafield)

        #This moves on to the next TLV
        lldpPayload = lldpPayload[2 + tlv_len:]

# if subtype for tlvstuffz = '\x00\x80\xC2\x01' then the next two bytes will contain the VLAN ID which needs to be performed using an unpack with !H

    # if tlv_type == 0x7f:
    #     _tlv_oui = unpack("!BBB", tlv_TotalPayload[:3])
    #     tlv_subtype = unpack("!B", tlv_TotalPayload[3:3 + 1])[0]
    #     tlv_TotalPayload = tlv_TotalPayload[3 + 1:]
    # print tlv_header
    # print "****************_ETHERNET_FRAME_****************"
    # print "Type:            ", binascii.hexlify(ethernetHeaderProtocol)
    # print "************************************************"
# import os
# import sys
# import binascii
# with open("output_tcpdump.alex") as f:
#     f.seek(40)
#     data = f.read()

#     #print data
#     print binascii.hexlify(data)
#     print type(data)
#     print data[0:14]

#Ethernet Frame
# +----------+------------+-----------+-----------+-----+
# | DEST MAC | SOURCE MAC | ETHERTYPE | User Data | FCS |
# +----------+------------+-----------+-----------+-----+
# |        6 |          6 |         2 | 46-1500   |   4 |
# +----------+------------+-----------+-----------+-----+

#TLV Frame (from userdata from ethernet frame)
# +----------+-----------------+------------+--------------+
# | TLV Type | TLV information | ID/Subtype |   Payload    |
# +----------+-----------------+------------+--------------+
# | 7 bits   | 9 bits          | 1 byte     | 0-511 Octets |
# +----------+-----------------+------------+--------------+

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