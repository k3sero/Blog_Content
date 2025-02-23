import os, random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, isPrime

FLAG = os.getenv("FLAG", "HackOn{goofy_flag}")

message = """
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│This challenge uses the Pedersen Commitment Scheme to prove the knowledge of a secret to the server.│
│                       Can you convince me that you know the flag???                                │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
"""


def gen_params():
    """
    p = getPrime(512)
    q = 2*p + 1
    while not isPrime(q):
        p = getPrime(512)
        q = 2*p + 1
    """
    q = 17032131111613663616220932453285657100875982798803654483825551961255401977190250879374328409931719910151624310573638554219448137843402731248609029551378719
    g = random.randint(2, q-1)
    h = random.randint(2, q-1)

    return  q, g, h


print(message)

q,g,h = gen_params()
x = bytes_to_long(FLAG[:len(FLAG)//2].encode())
y = bytes_to_long(FLAG[len(FLAG)//2:].encode())
A = pow(g, x, q)*pow(h, y, q) % q

print(f"q = {q}\ng = {g}\nh = {h}\nA = {A}")

history = {"T":[], "s1":[], "s2":[]}
for _ in range(5):
    print(f"Round {_} to convince me, send  g^t1 * h^t2 mod q")

    k = random.randint(2, q-1)
    print(f"{k = }")

    T = int(input(">>> "))
    if T in history["T"]:
        print("Don't try to fool me")
        exit()
    history["T"].append(T)

    print("Now give me, s1 = t1 + k*x mod q and s2 = t2 + k*y mod q")
    s1 = int(input(">>> "))
    s2 = int(input(">>> "))

    if s1 in history["s1"] or s2 in history["s2"]:
        print("Don't try to fool me")
        exit()

    history["s1"].append(s1)
    history["s2"].append(s2)
    
    if pow(g, s1, q)*pow(h, s2, q) % q != T*pow(A, k, q) % q:
        exit()

print(f"Okay, not bad: {FLAG}")