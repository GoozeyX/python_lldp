import os, sys
import socket
import struct
import binascii
import subprocess
import re
import fcntl
import ctypes
import signal

ETH_P_ALL = 0x0003
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

def exit_handler(signum, frame):
    """ Exit signal handler """

    capture_sock = frame.f_locals['capture_sock']
    interface_name = frame.f_locals['interface_name']

    promiscuous_mode(interface_name, capture_sock, False)
    print("Abort, %s exit promiscuous mode." % interface_name)

    sys.exit(1)

# Enable promiscuous mode from http://stackoverflow.com/a/6072625
def promiscuous_mode(interface, sock, enable=False):
    ifr = ifreq()
    ifr.ifr_ifrn = interface
    fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)
    ifr.ifr_flags |= IFF_PROMISC
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)

def run_linux_socket(interface, max_capture_time):
    
    rawSocket = socket.socket(17, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((interface, ETH_P_ALL))

    promiscuous_mode(interface, rawSocket, True)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGALRM, exit_handler)
    signal.alarm(max_capture_time)
    while True:
        packet = rawSocket.recvfrom(65565)
        packet = packet[0]
        lldpPayload = packet[14:]
        ethernetHeaderTotal = packet[0:14]

        ethernetHeaderUnpacked = struct.unpack("!6s6s2s", ethernetHeaderTotal)
        ethernetHeaderProtocol = ethernetHeaderUnpacked[2]

        if ethernetHeaderProtocol != '\x88\xCC':
            continue
        a, b, c, d = parse_lldp_packet_frames(lldpPayload)

def parse_lldp_packet_frames(lldpPayload, interfacename=None, capture_sock=None):

    while lldpPayload:
    #[0] at the end of the unpack is because of the tuple returnvalue
    #!H unpacks as an unsigned short, which has a size of two bytes, which is what we need because the TLV "header" is 9 and 7 bits long (2bytes)
    #The right bitshift by 9 bits shifts away the length part of the TLV, leaving us with the TLV Type
    #The bitmask gives us the length of the real payload by masking the first 7 bits with a 0000000111111111 mask (0x01ff in hex)
    #lldpDU is the 3rd-Nth byte of the TLV Frame
    #lldpDU: we need to add +2 bytes because the address space changes when we cut off the header ( see http://standards.ieee.org/getieee802/download/802.1AB-2009.pdf page 24)
    #if tlvtype is 4 then datafield must start at 0 because of the payload structure for Port Descriptions (see IEEE PDF)
        tlv_header = struct.unpack("!H", lldpPayload[:2])[0]
        tlv_type = tlv_header >> 9
        tlv_len = (tlv_header & 0x01ff)
        lldpDU = lldpPayload[2:tlv_len + 2]
        if tlv_type == 127:
            tlv_oui = lldpDU[:3]
            tlv_subtype = lldpDU[3:4]
            tlv_datafield = lldpDU[4:tlv_len]
            if tlv_oui == "\x00\x80\xC2" and tlv_subtype == "\x01":
                VLAN_ID = struct.unpack("!H", tlv_datafield)

        elif tlv_type == 0:
            print "TLV Type is ZERO, Breaking the while loop"
            break
        else: 
            print tlv_type
            tlv_subtype = "" if tlv_type is 4 else struct.unpack("!B", lldpDU[0:1])
            startbyte = 0 if tlv_type is 4 else 1
            tlv_datafield = lldpDU[startbyte:tlv_len]

        if tlv_subtype == 4:
            Port_Description = tlv_datafield
        elif tlv_subtype == 2:
            Ethernet_Port_Id = tlv_datafield
        elif tlv_subtype == 5:
            Switch_Name = tlv_datafield
        else:
            pass

        lldpPayload = lldpPayload[2 + tlv_len:]

        promiscuous_mode(interfacename, capture_sock, False)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(0)

    return VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id

def get_linux_interfacenames():
    # commenting this out for demo tests
    # interface_list = os.listdir("/sys/class/net")
    # return interface_list
    return ["eth0"]


def get_aix_interfacenames():
    output = subprocess.Popen("lsdev -l ent\*", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    interface_list = re.findall(r"^(ent?\d*).*$", str(output), re.M)
    return interface_list

def run_snoop(interface):
    pass

def run_tcpdumpaix(interface):
    pass

def parse_snoopdump():
    import thread

    with open("output_tcpdump.alex") as f:
        f.seek(40)
        data = f.read()

        #print data
        print binascii.hexlify(data)
        print type(data)
        print binascii.hexlify(data[0:14])

def main():
    max_capture_time = 90
    networkname_list = get_linux_interfacenames()

    for interface in networkname_list:
        run_linux_socket(interface, max_capture_time)


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

# import os
# import sys
# import binascii
# with open("output_tcpdump.alex") as f:
#     f.seek(40)
#     data = f.read()

#     #print data
#     print binascii.hexlify(data)
#     print type(data)
#     print binascii.hexlify(data[0:14])



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

# TLV Type 127 Frames
# +----------+-----------------+---------+---------+--------------------+
# | TLV Type | TLV information |   OUI   | subtype | Information string |
# +----------+-----------------+---------+---------+--------------------+
# | 7 bit    | 9 bit           | 3 bytes | 1 byte  | 0-507bytes         |
# +----------+-----------------+---------+---------+--------------------+

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