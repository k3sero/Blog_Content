from Crypto.Util.number import bytes_to_long, long_to_bytes


def decrypt_block(msg, key_list):
    m = bytes_to_long(msg)
    K = key_list
    msk = (1 << (64//2)) - 1

    s = 0x9e3779b9 << 5
    for i in range(32):
        m1 = m & msk
        m0 = m >> (64//2)
        
        m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
        m1 &= msk
        m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
        m0 &= msk
        
        s -= 0x9e3779b9
        
        m = ((m0 << (64//2)) + m1) & ((1 << 64) - 1)

    return long_to_bytes(m)


key_hex = "850c1413787c389e0b34437a6828a1b2"
cipher_hex = "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"

key_bytes = bytes.fromhex(key_hex)
cipher_bytes = bytes.fromhex(cipher_hex)

key_long = bytes_to_long(key_bytes)
cipher_long = bytes_to_long(cipher_bytes)

key_list = [bytes_to_long(key_bytes[i:i+64//16]) for i in range(0, len(key_bytes), 64//16)]


# Cuidado Pad msg = pad(msg, 64//8)
blocks = [cipher_bytes[i:i+64//8] for i in range(0, len(cipher_bytes), 64//8)]

plaintext_blocks = [decrypt_block(block, key_list) for block in blocks]

plaintext = b''.join(plaintext_blocks)
print(plaintext)