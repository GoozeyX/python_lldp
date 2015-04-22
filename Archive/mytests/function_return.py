import os, sys, subprocess, re

def get_networklist(osnameonly=None):
    """Get Operating system type so that we can choose which method to use to get the LLDP data"""
    osname = subprocess.Popen("uname -s", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()

    def get_linux_interfacenames():
        interface_list = os.listdir("/sys/class/net")
        return interface_list

    def get_aix_interfacenames():
        output = subprocess.Popen("lsdev -l en\*", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
        interface_list = re.findall(r"^(ent?\d*).*$", str(output), re.M)
        return interface_list

    if osnameonly is None:
        return {
            'Linux': get_linux_interfacenames(),
            'AIX': get_aix_interfacenames(),
        }[osname]
    else:
        return osname


# for i in get_networklist():
#     print i

var1 = get_networklist(osnameonly=True)
print var1
