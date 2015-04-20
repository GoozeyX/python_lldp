import signal
import subprocess
import re
import os
import sys
import time

def evaluate_aix():
# figure out a way to track subprocess calls and their pid and kill them when exiting, also google "at exit" signals because alarm can work incorrectly when buffer overflow occur

    # subprocess.call(['tcpdump', '-i', interface, '-s', '1500', '-c1', '-w', '/tmp/'+interface+'outfile', 'ether', 'proto', '0x88cc'])
    # tcpdump -i en8 -s 1500 -c1 -w output_tcpdump.alex ether proto 0x88cc <--- CALL THIS SHIT yo lol!

    # //perhaps i should try a capture one function... and then simply start a killtimer?
    interface = "eth0"
    proc = subprocess.Popen(['tcpdump', '-i', interface, '-s', '1500', '-w', '/tmp/'+interface+'outfile'])
    time.sleep(20)
    proc.kill()

    print "lol"
    # time.sleep(5)
    # with open("/tmp/eth0outfile", "w") as f:
    #     data = f.readlines()

    #     for line in data:
    #         print data
    # proc.kill()

#     with open(path+interface, 'w') as f: #TODO write mode 
#         context = {
#             "vlanid": VLAN_ID,
#             "ethernetportid": Ethernet_Port_Id,
#             "portdescription": Port_Description,
#             "switchname": Switch_Name,
#             }
#         template = """VLANID={vlanid}
# ETHERNETPORTID={ethernetportid}
# PORTDESCRIPTION={portdescription}
# SWITCHNAME={switchname}"""
        
#         f.write(template.format(**context))

if __name__ == '__main__':
    evaluate_aix()