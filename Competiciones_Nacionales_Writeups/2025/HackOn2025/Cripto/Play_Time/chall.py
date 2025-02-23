from xorshiro256 import Xoshiro256estrellaestrella
from hashlib import sha512
from secrets import randbits
from Crypto.Util.number import getPrime

FLAG = b"HackOn{??-_-??}"

rng = Xoshiro256estrellaestrella([randbits(64) for _ in range(4)])
def xor(a,b):
    return bytes(x ^ y for x,y in zip(a,b))
def otp():
    return  (rng()<< 128) | (rng()<<64) | rng()
def encrypt(message, key):
    return xor(message,key).hex()

def lets_play():
    eee = [otp() for _ in range(5)]
    hhh = int(sha512(b"What is going on????").hexdigest(),16)
    www = int(sha512(b"-_-").hexdigest(),16)
    for _ in range(5):
        print(www*(hhh*getPrime(400) + eee[_]))
lets_play()
print(f"Of course take the flag: {encrypt(FLAG,otp().to_bytes(24,'big') + otp().to_bytes(24,'big') + otp().to_bytes(24,'big') + otp().to_bytes(24,'big'))}")