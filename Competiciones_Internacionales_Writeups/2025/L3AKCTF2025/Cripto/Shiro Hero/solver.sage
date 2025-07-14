import z3
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Parámetros de la curva
n_ecdsa = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MASK64 = (1 << 64) - 1

# Leaks del PRNG
leaks = [
    0x785a1cb672480875,
    0x91c1748fec1dd008,
    0x5c52ec3a5931f942,
    0xac4a414750cd93d7
]

# Datos de la firma
H = 9529442011748664341738996529750340456157809966093480864347661556347262857832209689182090159309916943522134394915152900655982067042469766622239675961581701969877932734729317939525310618663767439074719450934795911313281256406574646718593855471365539861693353445695
r_sig = 54809455810753652852551513610089439557885757561953942958061085530360106094036
s_sig = 42603888460883531054964904523904896098962762092412438324944171394799397690539

ciphertext_hex = "404e9a7bbdac8d3912d881914ab2bdb924d85338fbd1a6d62a88d793b4b9438400489766e8e9fb157c961075ad4421fc"

def _rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & MASK64

# Función de temperado
def temper(s1):
    x = (s1 * 5) & MASK64
    x = _rotl(x, 7)
    x = (x * 9) & MASK64
    return x

# Función de actualización del estado en Z3
def next_state_z3(state):
    s0, s1, s2, s3 = state
    t = s1 << 17
    s2_t = s2 ^ s0
    s3_t = s3 ^ s1
    s1_t = s1 ^ s2_t
    s0_t = s0 ^ s3_t
    s2_t = s2_t ^ t
    s3_t = z3.RotateLeft(s3_t, 45)
    return [s0_t, s1_t, s2_t, s3_t]

# Resolver con Z3 para el estado inicial
s0, s1, s2, s3 = z3.BitVecs('s0 s1 s2 s3', 64)
solver = z3.Solver()
state = [s0, s1, s2, s3]

for i in range(4):
    solver.add(state[1] == leaks[i])
    state = next_state_z3(state)

if solver.check() != z3.sat:
    print("No solution found")
    exit(1)

model = solver.model()
s0_val = model[s0].as_long()
s1_val = model[s1].as_long()
s2_val = model[s2].as_long()
s3_val = model[s3].as_long()
print("Estado inicial recuperado:")

# Función de actualización del estado en Python
def next_state_py(state):
    s0, s1, s2, s3 = state
    t = (s1 << 17) & MASK64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = _rotl(s3, 45)
    return [s0, s1, s2, s3]

# Simular 4 actualizaciones
state = [s0_val, s1_val, s2_val, s3_val]
for _ in range(4):
    state = next_state_py(state)

# Obtener nonce k utilizado
k_raw = state[1]
k = temper(k_raw)
print(f"Nonce k: {k}")

# Calcular clave privada d
H_mod = H % n_ecdsa
d = ((s_sig * k - H_mod) * pow(r_sig, -1, n_ecdsa)) % n_ecdsa
print(f"Clave privada d: {d}")

# Derivar clave AES y descifrar
key = sha256(long_to_bytes(d)).digest()
iv = bytes.fromhex(ciphertext_hex[:32])
ct = bytes.fromhex(ciphertext_hex[32:])
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)
print(f"[+] Flag: {flag.decode()}")