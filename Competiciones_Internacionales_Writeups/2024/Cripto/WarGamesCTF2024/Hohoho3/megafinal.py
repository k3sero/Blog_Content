import hashlib
from Crypto.Util.number import *

# Valor hexadecimal dado
hex_value = "8b77b144816eefb40c1bf299da81629a"

# Convertir el valor hexadecimal a entero
token = int(hex_value, 16)

# Deshacer el XOR con (1 << 128) - 1
crc = token ^ ((1 << 128) - 1)

# Mostrar el valor de crc original

print("El valor de crc recuperado es:", crc)

def generateToken(name, m):
    data = name.encode(errors="surrogateescape")
    crc = (1 << 128) - 1

    print(f"Este es el crc inicial {crc}")

    for b in data:

        print(f"Este es el valor de b: {b}")
        crc ^= b
        print(f"Este es el resultado de los bytes: {bin(crc)}")
        print(f"Este es el crc ^ b : {crc}")


    return 1



#name = "\x7f"

name = str(input("Enter your name: "))
print(f"Valor de name es : {name}")

m = m = getRandomNBitInteger(128)
print(f"Este es el m generado: {m}")
print(f"")
token = generateToken(name, m)
print(f"Este es el resultado final: {token}")


