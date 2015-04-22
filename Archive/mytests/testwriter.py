import os

path = "/opt/sysdoc/lldp_data/"
try:
    os.makedirs(path, mode=0755)
except:
    pass
interface = "eth1"
text = "lol win"
with open(path+interface, "w") as f:
    f.write("%s" % text)