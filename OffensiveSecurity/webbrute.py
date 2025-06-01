#!/usr/bin/python3

import requests
import argparse
import sys
from colorama import Fore

# Using argparse for accepting the arguments for the functionality / help menu
parser = argparse.ArgumentParser(description='Tool to brute force web directories.')
parser.add_argument('url', metavar='url', type=str, help='Enter the target website: https://example.com')
parser.add_argument('wordlist', metavar='wordlist', type=str, help='Enter path to wordlist: /path/to/wordlist.txt')
args = parser.parse_args()

url = args.url
wordlist = args.wordlist

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
        finder(url, wordlist)
        break
    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(0)
    except ValueError:
        print("\n\n")
