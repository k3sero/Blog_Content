from pwn import *
from tqdm import tqdm

r = remote("krusty-katering.ctf.umasscybersec.org", 1337)

orders = {b'Bran Flakes': 30,
          b"SpongeBob's Sundae": 370,
          b'Aged Patty': 600,
          b'Krabby Fries':450,
          b'Fried Oyster Skins':120,
          b'Holographic Meatloaf': 550,
          b'Seanut Brittle Sandwich': 90,
          b'Pretty Patty Combo': 520,
          b'Banana': 15,
          b'Popcorn': 60}

cookers = [0]*10

for _ in range(5):

  r.recvuntil(b"Time to beat: ")
  time_to_beat = r.recvuntil(b"\nOrder #1")[:-10]

  for i in tqdm(range(1000)):

    r.recvuntil(b": ")
    order = r.recvuntil(b"\n").strip()
    r.recvuntil(b"Estimated time to cook: ")
    time_order = r.recvuntil(b"\n").strip()

    r.recvuntil(b"Which cook should handle this job? [1-10]")
    index_cooker = cookers.index(min(cookers))
    r.sendline(str(index_cooker + 1).encode())
    cookers[index_cooker] += orders[order]
    r.recvuntil(b"\n\n")
    print(cookers)

r.interactive()