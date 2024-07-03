# This is a tool to brute force web directories, return valid webpages found.

import requests
import sys
from colorama import Fore

def finder(url, wordlist):

    print("Attacking {} with wordlist: {}".format(url, wordlist))

    # Read the contents of the wordlist:
    with open(wordlist, "r") as f:
        wordlist = f.read().splitlines()

    for dir in wordlist:
        directory_url = url + "/" + dir
        response = requests.get(directory_url)

        if response.status_code == 200:
            print(f"{Fore.GREEN}[+] Found: ", directory_url)

while True:
    try:
        url, wordlist = input(
            "Enter target and wordlist: https://website.com /path/to/wordlist\n\n").split()
        finder(url, wordlist)
        break
    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(0)
    except ValueError:
        print("\n\n")
