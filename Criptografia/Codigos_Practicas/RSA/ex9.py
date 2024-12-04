"""
Nombre del archivo: ex9.py
Descripción: Este módulo contiene la funciones del ejercicio 9.
Autor: Carlos Marín Rodríguez

NOTA: Funciones NO testeadas correctamente por falta de tiempo (Están en mantenimiento).
"""

import random

def elgamal_encrypt(text, public_key, g, q, k):
    """
    Cifra un mensaje utilizando el cifrado ElGamal.

    Parámetros:
    - text (str): El mensaje a cifrar.
    - public_key (int): La clave pública del receptor (g^a mod q).
    - g (int): Parámetro público elegido en común.
    - q (int): Número primo público elegido en común.
    - k (int): Clave para ambos.

    Retorna:
    - tuple: (g^k mod q, [C1, C2, ...]), donde:
      - g^k mod q es el componente enviado por el emisor.
      - [C1, C2, ...] son los bloques cifrados del mensaje.
    """
    # Convertir el mensaje a formato numérico.
    num_message = ''.join(f"{ord(char):02}" for char in text)
    
    # Dividir en bloques de tamaño dígitos(q) - 1.
    block_size = len(str(q)) - 1
    blocks = [num_message[i:i+block_size] for i in range(0, len(num_message), block_size)]
    
    # Completar bloques incompletos con '30' y/o '0'.
    if len(blocks[-1]) < block_size:
        padding_length = block_size - len(blocks[-1])
        blocks[-1] += '30' * (padding_length // 2) + '0' * (padding_length % 2)
    
    # Convertir bloques a enteros.
    blocks = [int(block) for block in blocks]
    
    # Elegir un k aleatorio tal que 2 ≤ k ≤ q-2.
    k = random.randint(2, q - 2)
    
    # Calcular g^k mod q.
    g_k = pow(g, k, q)
    
    # Calcular g^(ak) mod q.
    g_ak = pow(public_key, k, q)
    
    # Cifrar los bloques.
    encrypted_blocks = [(block * g_ak) % q for block in blocks]
    
    return g_k, encrypted_blocks

def elgamal_decrypt(g_k, C, private_key, g, q):
    """
    Descifra un mensaje cifrado con ElGamal.

    Parámetros:
    - g_k (int): Componente enviado por el emisor, calculado como g^k mod q.
    - C (list of int): Lista de bloques cifrados.
    - private_key (int): Clave privada del receptor (a).
    - g (int): Parámetro público elegido en común.
    - q (int): Número primo público elegido en común.

    Retorna:
    - str: El mensaje descifrado como texto.
    """
    # Paso 1: Calcular g^(ak) mod q usando la clave privada del receptor.
    g_ak = pow(g_k, private_key, q)
    
    # Paso 2: Calcular el inverso modular de g^(ak) mod q.
    g_ak_inv = pow(g_ak, -1, q)
    
    # Paso 3: Descifrar cada bloque.
    M_blocks = [(block * g_ak_inv) % q for block in C]
    
    # Paso 4: Convertir los bloques numéricos en texto.
    message = ''.join([str(block).zfill(len(str(q)) - 1) for block in M_blocks])
    
    # Quitar cualquier relleno adicional (30 corresponde a espacio en ASCII).
    while message.endswith('30'):
        message = message[:-2]
    
    # Convertir el mensaje numérico en texto.
    decoded_message = ''.join(
        chr(int(message[i:i+2])) for i in range(0, len(message), 2)
    )
    
    return decoded_message

'''
#Testing. Parámetros en testeo.
print("=======================================")
print("               Cifrado")
print("=======================================\n")
# Parámetros públicos.
q = 13  # Número primo.
g = 2   # Base elegida.
k = 7   # Clave
public_key = 7  # g^a mod q (clave pública del receptor).

# Mensaje a cifrar.
text = "hola"

# Cifrar el mensaje
g_k, encrypted_blocks = elgamal_encrypt(text, public_key, g, q, k)
print("g^k mod q:", g_k)
print("Bloques cifrados:", encrypted_blocks)

print("\n=======================================")
print("              Descifrado")
print("=======================================\n")

# Parámetros públicos y clave privada
q = 13  # Número primo
g = 2    # Base elegida
private_key = 11  # Clave privada del receptor obtenida en el cifrado.

# Descifrar el mensaje
decrypted_message = elgamal_decrypt(g_k, encrypted_blocks, private_key, g, q)
print("Mensaje descifrado:", decrypted_message)
'''