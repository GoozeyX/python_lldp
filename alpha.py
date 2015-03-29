import socket

## Magic constants from `/usr/include/linux/if_ether.h`:
ETH_P_ALL = 0x0003
ETH_ALEN = 6
ETH_HLEN = 14

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
    packet = rawSocket.recvfrom(65565)
    #this is because the packets sniffed/received look like this:
    #('E \x00(\xcc\xff\x00\x000\x06jrJ}G\x13\xc0\xa8\x01\x06\x01\xbb\xa3\xdc\x0b\xbeJ0\x1aFbtP******', ('xxx.xxx.xxx.xxx', 0))
    packet = packet[0]
    eth_protocol, eth_payload = unpack_ethernet_frame(packet)[3:]


#http://www.thegeekstuff.com/2012/03/ip-protocol-header/ <-- IP Protocol Information