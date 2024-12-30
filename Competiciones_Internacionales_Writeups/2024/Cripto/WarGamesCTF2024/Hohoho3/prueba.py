import hashlib
from Crypto.Util.number import *

# Valor hexadecimal dado
hex_value = "5536faf1a6b25cc4731f7ef2f16cf714"

# Convertir el valor hexadecimal a entero
token = int(hex_value, 16)

# Deshacer el XOR con (1 << 128) - 1
crc = token ^ ((1 << 128) - 1)

# Mostrar el valor de crc original

#print("El valor de crc recuperado es:", crc)

def generateToken(name, m):
    data = name.encode(errors="surrogateescape")
    crc = (1 << 128) - 1

    print(f"Este es el crc inicial {crc}")

    for b in data:

        print(f"Este es el valor de b: {b}")

        crc ^= b
        print(f"Este es el resultado de los bytes: {crc}")
        print(f"Este es el crc ^ b : {crc}")

        for _ in range(8):

            #print(f"Este es crc antes de actualizarse {crc}")

            print(f"Valor de crc >> 1 : {crc >> 1}")
            print(f"Valor de -(crc & 1) : {-(crc & 1)}")
            print(f"Segunda parte del XOR {(m & -(crc & 1))}")
            print(f"")

            crc = (crc >> 1) ^ (m & -(crc & 1))

            print(f"Este es crc despues de actualizarse {crc}")



    print(crc)

    return hex(crc ^ ((1 << 128) - 1))[2:]




#name = "\x7f"

name = str(input("Enter your name: "))
print(f"Valor de name es : {name}")

m = 314320694760960186183647210177372466087
print(f"Este es el m generado: {m}")
print(f"")
token = generateToken(name, m)
print(f"Este es el resultado final: {token}")


token = int(hex_value, 16)

token = token ^ ((1 << 128) - 1)
print(token)



(token >> 1)
print(token)

(token >> 1)
print(token)

(token >> 1)
print(token)

(token >> 1)
print(token)

(token >> 1)
print(token)

(token >> 1)
print(token)

(token >> 1)
print(token)