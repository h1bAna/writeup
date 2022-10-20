from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import FLAG
from random import choices
import string

def encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(msg)
    return cipher.nonce.hex(), ct.hex()

def decrypt(ct, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, initial_value=nonce, nonce=b"")
    msg = cipher.decrypt(ct)
    return msg

if __name__ == "__main__":
    chars = string.ascii_uppercase
    s = ''.join(choices(chars, k=16))
    key = get_random_bytes(16)
    msg = f"Welcome Hackers, this cryptosystem is under construction, can you please decrypt the 's' for me {s}."
    nonce, ct = encrypt(msg.encode(), key)
    print(f"Nonce: {nonce}")
    print(f"Ciphertext: {ct}")
    try:
        _nonce = bytes.fromhex(input("Your nonce: "))
        _nonce = _nonce + bytes(16 - len(_nonce))
        _ct = bytes.fromhex(input("Your ciphertext: "))
        _s = decrypt(_ct, key, _nonce)
        if _s == s.encode():
            print(FLAG)
        else:
            print(f"Your 's': {_s}\nNope!")
    except:
        quit()