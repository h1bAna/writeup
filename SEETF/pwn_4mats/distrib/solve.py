import subprocess
from pwn import *
context.log_level="debug"

#nc fun.chall.seetf.sg 50001
p = remote("fun.chall.seetf.sg",50001)
print('d')
p.sendafter(b'register: \n',b'ba')
print('d')
proc = subprocess.Popen(['./test'],stdout=subprocess.PIPE)
line = proc.stdout.readline()
p.sendafter(b'you?\n',b'1\n')




p.sendafter(b'Guess my favourite number!\n',line)
print(p.recvline())
p.interactive()