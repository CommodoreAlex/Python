# Importing required libraries
import socket
import pyfiglet
import sys
from datetime import datetime
from colorama import init
from termcolor import colored

# Get the address from the user
ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)
target = input(str("Enter a target IP address: "))

print("_" * 50)
print("Scanning target: " +  target)
print("Started at: " + str(datetime.now()))
print("_" * 50)


try:
        for port in range(1,1024):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)

                result = s.connect_ex((target,port))
                if result == 0:
                        f = open('results.txt', 'a')
                        print(colored(f"Port {port} is open", 'green'))
                        # Printing what is found to the results file
                        print(f"Port {port} is open", file=f)
                s.close()

except KeyboardInterrupt:
        print("\n\n Exiting.")
        sys.exit()

except socket.error:
        print(colored("\n\n Host not responding.", 'red'))
        sys.exit()
