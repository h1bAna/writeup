#!python3
from pwn import *
context.log_level = 'debug'
#nc 0.cloud.chals.io 30096
r = remote('0.cloud.chals.io', 30096)
payload = p64(int(r.recvline()[-15:-1], 16)) #u64(r.recvline()
print(payload)
# not solve yet