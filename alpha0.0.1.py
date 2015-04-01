import os, sys
import socket
import struct
import binascii
import subprocess
import re
import fcntl
import ctypes
import signal
import thread

ETH_P_ALL = 0x0003
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

def get_operatingsystem_type():
    """Get Operating system type so that we can choose which method to use to get the LLDP data"""
    osname = subprocess.Popen("uname", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
    return osname
class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

def exit_handler(signum, frame):
    """ Exit signal handler """

    rawSocket = frame.f_locals['rawSocket']
    interface = frame.f_locals['interface']

    promiscuous_mode(interface, rawSocket, False)
    print("Abort, %s exit promiscuous mode." % interface)

    sys.exit(1)

# Enable promiscuous mode from http://stackoverflow.com/a/6072625
def promiscuous_mode(interface, sock, enable=False):
    ifr = ifreq()
    ifr.ifr_ifrn = interface
    fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)
    if enable:
        ifr.ifr_flags |= IFF_PROMISC
    else:
        ifr.ifr_flags &= ~IFF_PROMISC
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
        VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id = parse_lldp_packet_frames(lldpPayload)
        break
    return VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id
def parse_lldp_packet_frames(lldpPayload):
    Switch_Name = None
    VLAN_ID = None
    Ethernet_Port_Id = None
    Port_Description = None

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
            # print tlv_type
            tlv_subtype = "" if tlv_type is 4 else struct.unpack("!B", lldpDU[0:1])
            startbyte = 0 if tlv_type is 4 else 1
            tlv_datafield = lldpDU[startbyte:tlv_len]

        if tlv_type == 4:
            Port_Description = tlv_datafield
        elif tlv_type == 2:
            Ethernet_Port_Id = tlv_datafield
        elif tlv_type == 5:
            Switch_Name = tlv_datafield
        else:
            pass

        lldpPayload = lldpPayload[2 + tlv_len:]


    return VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id

def get_linux_interfacenames():
    # commenting this out for demo tests
    # interface_list = os.listdir("/sys/class/net")
    # return interface_list
    return ["eth0"]


def get_aix_interfacenames():
    output = subprocess.Popen("lsdev -l en\*", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
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



if __name__ == '__main__':
    main()
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
