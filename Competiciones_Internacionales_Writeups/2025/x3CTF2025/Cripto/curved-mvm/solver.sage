from sage.all import *
import hashlib

# Función para convertir bytes a un entero largo
def bytes_to_long(byte_data):
    return int.from_bytes(byte_data, byteorder='big')

# Parámetros de la curva
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

F = GF(p)
EC = EllipticCurve(F, [a, b])
G = EC([Gx, Gy])
n = EC.order()

# Obtener una firma (r, s) para SAMPLE_MSG
SAMPLE_MSG = "hardcoded cuz reasons"
z = bytes_to_long(hashlib.sha1(SAMPLE_MSG.encode()).digest()) % n

# Valores de r y s obtenidos del servidor
r = 0x78a743145f397a221bd84e032e02349e9f1010fe3866c7f3d7b9f783e59c7d2f  # Reemplaza con el valor real de r
s = 0xf7ffc9d5cb436db8cfdcf3b5e88f51c071cf13adc567ce025d0369aaf63d539  # Reemplaza con el valor real de s

# Fuerza bruta sobre k
found = False
for k in range(2**18):
    R = k * G
    if R == EC(0):  # Verificar si R es el punto en el infinito
        continue  # Saltar este valor de k
    r_candidate = ZZ(R.x()) % n
    if r_candidate == r:
        print(f"Found k: {k}")
        # Recuperar la clave secreta
        SECRET_KEY = (s * k - z) * inverse_mod(r, n) % n
        print(f"Recovered SECRET_KEY: {SECRET_KEY}")
        found = True
        break

if not found:
    print("No se encontró el valor de k.")

# Firmar el mensaje REQUIRED_MSG con la clave secreta recuperada
if found:
    REQUIRED_MSG = "mvm mvm mvm"
    z_required = bytes_to_long(hashlib.sha1(REQUIRED_MSG.encode()).digest()) % n
    k_required = (randint(0, 2**18 - 1) + 2) % n  # Generar un número aleatorio de 18 bits
    R_required = k_required * G
    if R_required == EC(0):  # Verificar si R_required es el punto en el infinito
        print("Error: R_required es el punto en el infinito.")
    else:
        r_required = ZZ(R_required.x()) % n
        s_required = (inverse_mod(k_required, n) * (z_required + r_required * SECRET_KEY)) % n
        print(f"Firma para REQUIRED_MSG: r = {hex(r_required)}, s = {hex(s_required)}")
