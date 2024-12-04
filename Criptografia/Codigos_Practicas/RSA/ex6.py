"""
Nombre del archivo: ex6.py
Descripción: Este módulo contiene la funciones del ejercicio 6.
Autor: Carlos Marín Rodríguez
"""

from ex3 import *
from ex4 import *
from ex5 import *

def rsaciphertext(text, public_key):
    """
    Cifra un texto usando la clave pública (n, e).
    
    Parámetros:
    - text: El texto a cifrar.
    - public_key: Tupla (e, n) que representa la clave pública.
    
    Retorna:
    - Lista de bloques cifrados.
    """
    # Convertir texto a su equivalente numérico
    num_str = text_to_numbers(text)
    e, n = public_key

    # Preparar bloques numéricos
    block_size = len(str(n))-1  
    blocks = preparenumcipher(num_str, block_size)

    # Cifrar los bloques
    encrypted_blocks = rsacipher(blocks, public_key)
    
    return encrypted_blocks

def rsadeciphertext(blocks, private_key):
    """
    Descifra bloques cifrados y convierte a texto utilizando la clave privada (n, d).
    
    Parámetros:
    - blocks: Bloques cifrados a descifrar.
    - private_key: Tupla (n, d) que representa la clave privada.
    
    Retorna:
    - El texto descifrado.
    """
    d, n = private_key

    # Descifrar los bloques
    decrypted_blocks = rsadecipher(blocks, private_key)

    # Unir los bloques descifrados
    block_size = len(str(n))-1
    combined = preparetextdecipher(decrypted_blocks, block_size)
    print(f"full cadena: {combined}")

    # Convertir la cadena numérica de vuelta a texto
    decrypted_text = numbers_to_text(combined)
    
    return decrypted_text

'''
# Testing. Ejemplos
# Ejemplo de claves públicas y privadas (pequeñas para facilidad de prueba)
public_key = (31, 7073)  # (e, n)
private_key = (2071, 7073)  # (d, n)

# Texto a cifrar
text = "abcdefghijklmnopqrstuvwxyz"

# Cifrar el texto
encrypted_blocks = rsaciphertext(text, public_key)
print("Texto cifrado (bloques):", encrypted_blocks)

# Descifrar el texto
decrypted_text = rsadeciphertext(encrypted_blocks, private_key)
print("Texto descifrado:", decrypted_text)
'''