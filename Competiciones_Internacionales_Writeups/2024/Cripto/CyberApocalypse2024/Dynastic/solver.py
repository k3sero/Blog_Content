def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def decrypt(m):
    flag = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi - i)
        flag += ech
    return flag

def load_data(filename):
    with open(filename) as f:
        f.readline()
        cipher = f.readline()
        return cipher


cipher = load_data('output.txt')
flag = decrypt(cipher)
print(f'HTB{{{flag}}}')