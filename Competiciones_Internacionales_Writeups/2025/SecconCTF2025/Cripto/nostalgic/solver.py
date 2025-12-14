from sage.all import *
from pwn import process, remote
from lll_cvp import find_ortho, reduce_mod_p


# io = process(["python3", "chall.py"])
io = remote("nostalgic.seccon.games", 5000)

io.recvuntil(b"my SPECIAL_MIND is ")
SPECIAL_MIND = bytes.fromhex(io.recvlineS())
io.recvuntil(b"special_rain_enc = ")
special_ct = bytes.fromhex(io.recvlineS())
io.recvuntil(b"special_rain_tag = ")
special_tag = bytes.fromhex(io.recvlineS())


def need():
    io.sendline(b"need")
    io.recvuntil(b"my MIND was ")
    return bytes.fromhex(io.recvlineS())


p = 2**130 - 5
M = 2**128

F = GF(p)
tags = [int.from_bytes(need(), "little") for _ in range(256)]
print("data collected")
dt = [t - tt for t, tt in zip(tags, tags[1:])]
vdt = vector(F, dt)
ot = find_ortho(p, vdt).BKZ()
# we assume that only the last two vector are errors
ot2 = find_ortho(p, *ot[:-2])
print("ot done")


def find_candidates():
    for sgn1 in (1, -1):
        guess_vdk = sgn1 * ot2[0]
        r2dm = vdt + guess_vdk * M
        guess_dm = min(reduce_mod_p(matrix(r2dm), p), key=lambda v: v.norm().n())
        for sgn2 in (1, -1):
            guess_r2 = F(r2dm[0] / (sgn2 * guess_dm[0]))
            if not guess_r2.is_square():
                print("not square")
                continue

            # we only need r^2 to forge the tag
            yield guess_r2


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


m = int.from_bytes(special_ct, "little")
for guess_r2 in find_candidates():
    print(f"{guess_r2 = }")
    t = int.from_bytes(special_tag, "little")
    for i in range(4):
        t += i * M
        dt = int.from_bytes(SPECIAL_MIND, "little") - t
        mp = m + F(dt) / guess_r2
        if mp > M:
            print("mp too large :(", mp)
            continue
        delta = xor(int(mp).to_bytes(16, "little"), special_ct)
        print(f"delta: {delta.hex()}")
        io.sendline(delta.hex())
io.interactive()
# SECCON{Listening_to_the_murmuring_waves_and_the_capricious_passing_rain_it_feels_like_a_gentle_dream}