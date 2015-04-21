import sys, os, subprocess


def get_solaris_interfacenames():
    osrelease = subprocess.Popen("uname -r", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
    if osrelease == "5.11":
        # output = subprocess.Popen("dladm show-dev -p", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
        # interface_list = [line.split()[0] for line in output.rstrip().split('\n')]
        output = subprocess.Popen("dladm show-phys -p -o link", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
        interface_list = [line.split()[0] for line in output.rstrip().split('\n')]
        print interface_list
        # for line in output.rstrip()split('\n'):
        #     print line.split()[0]
        #     print line
    else:
        print "sorry woops"

if __name__ == '__main__':
    get_solaris_interfacenames()


            # (name, rest) = line.split()[0], line.split()[1:]