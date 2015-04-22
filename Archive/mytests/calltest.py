import os
import subprocess


def get_os_type():
    output = subprocess.Popen("uname", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
    print output.strip()

get_os_type()
