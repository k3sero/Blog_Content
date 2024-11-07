from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256

p_hex = "dd6cc28d"
p_bytes = bytes.fromhex(p_hex)
p_long = bytes_to_long(bytes.fromhex(p_hex))    #3714892429

g_hex = "83e21c05"
g_bytes = bytes.fromhex(g_hex)
g_long = bytes_to_long(bytes.fromhex(g_hex))    #2212633605


A_hex = "cfabb6dd"
A_bytes = bytes.fromhex(A_hex)
A_long = bytes_to_long(bytes.fromhex(A_hex))    #3484137181

B_hex = "c4a21ba9"
B_bytes = bytes.fromhex(B_hex)
B_long = bytes_to_long(bytes.fromhex(B_hex))    #3298958249

ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'

# b obtenido de resolver el algoritmo discreto mediante Pohlig-Hellman (solved Daysa.py)
b_long = 1913706799
b_bytes = long_to_bytes(b_long)

c = pow(A_long, b_long, p_long)

hash = sha256()
hash.update(long_to_bytes(c))

key = hash.digest()[:16]

cipher = AES.new(key, AES.MODE_CBC, iv)

decrypted = cipher.decrypt(ciphertext)
print(decrypted)