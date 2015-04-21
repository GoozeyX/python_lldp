import os, sys
import socket
import struct
# import binascii
import subprocess
import re
import fcntl
import time
import signal
# from threading import Thread
# import threading
from multiprocessing import Process

#There is a really good chance this cannot be loaded on AIX and Solaris (also not needed due to us not using raw sockets)
try:
    import ctypes
    class ifreq(ctypes.Structure):
        _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                    ("ifr_flags", ctypes.c_short)]
except (ImportError, NameError) as e:
    print "Meh"
#Taken from the C Header Files 
ETH_P_ALL = 0x0003
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914


def get_networklist(osnameonly=None):
    """Get Operating system type so that we can choose which method to use to get the LLDP data"""
    osname = subprocess.Popen("uname -s", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
    print osname
    def get_linux_interfacenames():
        interface_list = os.listdir("/sys/class/net")
        return interface_list

    def get_aix_interfacenames():
        output = subprocess.Popen("lsdev -l en\*", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
        interface_list = re.findall(r"^(en\d*)\s+Available.*$", str(output), re.M)
        return interface_list

    def get_solaris_interfacenames():
        osrelease = subprocess.Popen("uname -r", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
        if osrelease == "5.10":
            output = subprocess.Popen("dladm show-dev -p", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
            interface_list = [line.split()[0] for line in output.rstrip().split('\n')]
        elif osrelease == "5.11":
            output = subprocess.Popen("dladm show-phys -p -o link", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
            interface_list = [line.split()[0] for line in output.rstrip().split('\n')]
        else:
            print "something went wrong here..."
        return interface_list


    if osnameonly is None:
        return {
            'Linux': get_linux_interfacenames,
            'AIX': get_aix_interfacenames,
            'SunOS': get_solaris_interfacenames,
        }[osname]()
    else:
        return osname
    # python case switch http://stackoverflow.com/questions/60208/replacements-for-switch-statement-in-python

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

def evaluate_aix(interface, max_capture_time):
# figure out a way to track subprocess calls and
    # signal.signal(signal.SIGINT, exit_handler_aix)
    # signal.signal(signal.SIGALRM, exit_handler_aix)
    # signal.alarm(max_capture_time)
    # tcpdump -i en8 -s 1500 -c1 -w output_tcpdump.alex ether proto 0x88cc
    process = subprocess.Popen(['tcpdump', '-i', interface, '-s', '1500', '-c1', '-w', '/tmp/'+interface+'outfile', 'ether', 'proto', '0x88cc'])
    time.sleep(62)
    if process.poll() is None:
        process.terminate()
    time.sleep(3)
    if process.poll() is None:
        process.kill()
        
    with open("/tmp/"+interface+"outfile") as f:
        f.seek(40)
        data = f.read()
        data = data[14:]
        VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id = parse_lldp_packet_frames(data)
    path = "/opt/sysdoc/lldp_data/"
    if not os.path.exists("/opt/sysdoc/lldp_data"):
        os.makedirs(path, mode=0755)
        
    with open(path+interface, 'w') as f: #TODO write mode 
        context = {
            "vlanid": VLAN_ID,
            "ethernetportid": Ethernet_Port_Id,
            "portdescription": Port_Description,
            "switchname": Switch_Name,
            }
        template = """VLANID={vlanid}
ETHERNETPORTID={ethernetportid}
PORTDESCRIPTION={portdescription}
SWITCHNAME={switchname}"""
        
        f.write(template.format(**context))

def evaluate_solaris(interface, max_capture_time):
# figure out a way to track subprocess calls and
    # signal.signal(signal.SIGINT, exit_handler_aix)
    # signal.signal(signal.SIGALRM, exit_handler_aix)
    # signal.alarm(max_capture_time)
    # tcpdump -i en8 -s 1500 -c1 -w output_tcpdump.alex ether proto 0x88cc
    process = subprocess.Popen(['tcpdump', '-i', interface, '-s', '1500', '-c1', '-w', '/tmp/'+interface+'outfile', 'ether', 'proto', '0x88cc'])
    time.sleep(62)
    if process.poll() is None:
        process.terminate()
    time.sleep(3)
    if process.poll() is None:
        process.kill()
        
    with open("/tmp/"+interface+"outfile") as f:
        f.seek(40)
        data = f.read()
        data = data[14:]
        VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id = parse_lldp_packet_frames(data)
    path = "/opt/sysdoc/lldp_data/"
    if not os.path.exists("/opt/sysdoc/lldp_data"):
        os.makedirs(path, mode=0755)
        
    with open(path+interface, 'w') as f: #TODO write mode 
        context = {
            "vlanid": VLAN_ID,
            "ethernetportid": Ethernet_Port_Id,
            "portdescription": Port_Description,
            "switchname": Switch_Name,
            }
        template = """VLANID={vlanid}
ETHERNETPORTID={ethernetportid}
PORTDESCRIPTION={portdescription}
SWITCHNAME={switchname}"""
        
        f.write(template.format(**context))


def evaluate_linux(interface, max_capture_time):
    print "inside thread now"
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
    promiscuous_mode(interface, rawSocket, False)

    # return VLAN_ID, Switch_Name, Port_Description, Ethernet_Port_Id
    path = "/opt/sysdoc/lldp_data/"

    if not os.path.exists("/opt/sysdoc/lldp_data"):
        os.makedirs(path, mode=0755)

    with open(path+interface, 'w') as f: #TODO write mode 
        context = {
            "vlanid": VLAN_ID,
            "ethernetportid": Ethernet_Port_Id,
            "portdescription": Port_Description,
            "switchname": Switch_Name,
            }
        template = """VLANID={vlanid}
ETHERNETPORTID={ethernetportid}
PORTDESCRIPTION={portdescription}
SWITCHNAME={switchname}"""
        
        f.write(template.format(**context))


        # write(template.format(**context))
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
                VLAN_ID = struct.unpack("!H", tlv_datafield)[0]

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


def main():
    max_capture_time = 70
    networkname_list = get_networklist()
    os_name = get_networklist(osnameonly=True)
    # print os_name
    evaluate_Function = {
        'Linux': evaluate_linux,
        'AIX': evaluate_aix,
    }

    processes = [Process(target=evaluate_Function[os_name], args=(interface, max_capture_time)) for interface in networkname_list] 
    print processes
    for x in processes:
        # x.daemon = True Bad idea really... 
        x.start()

def exit_handler(signum, frame):
    """ Exit signal handler """

    rawSocket = frame.f_locals['rawSocket']
    interface = frame.f_locals['interface']

    promiscuous_mode(interface, rawSocket, False)
    print("Abort, %s exit promiscuous mode." % interface)

    sys.exit(1)

def exit_handler_aix(signum, frame):
    print "Aborting AIX"
    sys.exit(0)

# def killtimer():
#     import time
#     time.sleep(3)


if __name__ == '__main__':
    main()

# Notes:
# Subprocess with timeout:
# http://stackoverflow.com/questions/1191374/subprocess-with-timeout