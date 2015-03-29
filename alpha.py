import socket
from struct import unpack


#Ethernet Frame: ( https://wiki.wireshark.org/Ethernet )
# ╔══════════════════╦════════════════════╦═════════════╦══════════╦═════╗
# ║ DEST MAC ADDRESS ║ SOURCE MAC ADDRESS ║ TYPE LENGTH ║ USERDATA ║ FSF ║
# ╠══════════════════╬════════════════════╬═════════════╬══════════╬═════╣
# ║                6 ║                  6 ║           2 ║ 46-1500  ║   4 ║
# ╚══════════════════╩════════════════════╩═════════════╩══════════╩═════╝
# Magic constants from `/usr/include/linux/if_ether.h`: (from github whisperraven)
# ETH_P_ALL = 0x0003
# ETH_ALEN = 6
# ETH_HLEN = 14

def unpack_ethernet_frame(packet):
    """ Unpack ethernet frame """

    eth_header = packet[0:ETH_HLEN]
    eth_dest_mac = unpack(UNPACK_ETH_HEADER_DEST, eth_header[0:ETH_ALEN])
    eth_src_mac = unpack(UNPACK_ETH_HEADER_SRC, eth_header[ETH_ALEN:ETH_ALEN*2])
    eth_protocol = unpack(UNPACK_ETH_HEADER_PROTO, eth_header[ETH_ALEN*2:ETH_HLEN])[0]
    eth_payload = packet[ETH_HLEN:]

    return (eth_header, eth_dest_mac, eth_src_mac, eth_protocol, eth_payload)


rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
    packet = rawSocket.recvfrom(65565)
    #this is because the packets sniffed/received look like this:
    #('E \x00(\xcc\xff\x00\x000\x06jrJ}G\x13\xc0\xa8\x01\x06\x01\xbb\xa3\xdc\x0b\xbeJ0\x1aFbtP******', ('xxx.xxx.xxx.xxx', 0))
    packet = packet[0]
    ethernetHeader = packet[0:14]
    ethrheader = struct.unpack("!6s6s2s",ethernetHeader)
    eth_protocol, eth_payload = unpack_ethernet_frame(packet)[3:]


#http://www.thegeekstuff.com/2012/03/ip-protocol-header/ <-- IP Protocol Information

# LLDP FRAME information:
# http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol

