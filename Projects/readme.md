# Python Programming Projects

### **Security & Penetration Testing Tools**

These scripts are designed to assist in various security testing and penetration tasks:

- **Cookiemonster.py**  
    A tool that sets up a local server to steal cookies from vulnerable web applications using Cross-Site Scripting (XSS) attacks. This script demonstrates the risks of XSS vulnerabilities by allowing attackers to intercept sensitive data such as session cookies.
    
- **DecodeXOR.py**  
    A script that showcases a basic XOR decryption technique, often used in Capture The Flag (CTF) challenges. The script decrypts encrypted data using a key array and reveals hidden information or flags.
    
- **Webbrute.py**  
    A simple brute-force tool designed to discover hidden web directories using a wordlist. It sends HTTP requests to a target URL, looking for valid directories. If a directory returns a successful status code (200), it’s reported as found.
    
- **WordpressIDs.py**  
    A tool for brute-forcing user IDs in WordPress blogs by sending requests to a target URL with different author IDs. This script is useful for identifying valid user IDs during penetration testing or CTF challenges.
- **Wifisniffer.py**
  
    This Python script uses the `scapy` library to capture and analyze Wi-Fi network packets. It begins by defining a network interface (e.g., `wlan0`) and includes functions to switch the interface into "monitor mode," which allows it to capture all Wi-Fi traffic in the vicinity, and revert it back to "managed mode" for normal operation. The `packet_handler` function processes captured packets, specifically Beacon frames from nearby access points, extracting key information like the SSID (network name), signal strength (in dBm), and encryption type (such as WPA2, WPA3, or WEP). The script enables monitor mode, captures packets for 10 seconds, and then disables monitor mode when finished.

### **File Manipulation & Encoding/Decoding**

These scripts focus on handling data, encoding techniques, and file manipulation:

- **Misfortune.py**  
    Designed for the **Misfortune CTF** challenge, this script dives deep into binary exploitation techniques, including **Return-Oriented Programming (ROP)**, **Procedure Linkage Table (PLT)**, and **Global Offset Table (GOT)**. It leverages **Pwntools** to automate the exploitation process, demonstrating how to bypass stack protections and execute **ret2libc** attacks.
    
- **Traverse.py**  
    A script for performing directory traversal attacks on web applications. It tests various payloads that attempt to access sensitive files such as `/etc/passwd` or `/windows/system32/drivers/etc/hosts`. This tool is useful for CTF challenges or penetration testing to exploit inadequate input validation and access restricted files.
    

### **System & Network Utilities**

These scripts serve to automate system administration and network security tasks:

- **Clean_ssh.py**  
    This script cleans up SSH keys by removing newlines and trailing spaces. It ensures that the SSH key is in a single line, which is often required for use in automation tasks or when embedding SSH keys in scripts.
    
- **Scanner.py**  
    A simple port scanner that checks for open ports on a specified target IP address. It attempts to connect to ports 1 through 1023 and reports which ports are open. The results are displayed in the terminal and saved to a `results.txt` file. It uses libraries like `socket`, `pyfiglet`, `colorama`, and `datetime` to enhance the scanning experience.
    
- **ClientSide.py**  
    This script generates a PowerShell reverse shell payload, base64 encodes it, and writes it in a format that can be used inside a VBA macro. This enables the execution of a reverse shell when the macro is run in a document.
    

### **Library Management App**

- **Library_app.py**  
    This Python script is a simple library management system designed to handle basic operations related to books and employees within a library. It allows administrators to add and manage employee data (name and phone number), view the list of employees, and add or delete books. The system ensures data security by using bcrypt for password hashing and allows only authorized users to access certain functionalities. It includes the creation of directories and files for storing data, and it ensures proper logging for all operations. The script also handles input sanitization, validation of phone numbers, and protects sensitive files with appropriate user group permissions. Additionally, it supports managing a list of books stored in a text file, ensuring no duplicate entries, and allows users to open, view, and delete books in the library.

### **AI and NLP Tools**

- Hugs.py 
    A script that uses a pre-trained GPT-2 model from **Hugging Face** and **PyTorch** to generate text based on a given prompt. The script allows for adjustable parameters such as temperature sampling, top-k sampling, and repetition penalty to control the diversity and quality of the generated text.

---
