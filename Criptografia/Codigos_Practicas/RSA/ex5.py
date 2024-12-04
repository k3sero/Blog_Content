"""
Nombre del archivo: ex5.py
Descripción: Este módulo contiene la funciones del ejercicio 5.
Autor: Carlos Marín Rodríguez
"""

def rsacipher(blocks, public_key):
    """
    Cifra una lista de bloques numéricos usando la clave pública (n, e) del algoritmo RSA.
    
    Parámetros:
    - blocks (list of int): Lista de bloques numéricos a cifrar. Cada bloque debe ser un número entero que representa un fragmento del mensaje a cifrar.
    - public_key (tuple): Tupla (n, e) que representa la clave pública en el sistema RSA.
        - e (int): El exponente público, que es un número elegido tal que sea coprimo con (p-1)*(q-1).
        - n (int): El módulo, el cual es el producto de dos números primos grandes p y q.
        
    
    Retorna:
    - list of int: Lista de bloques cifrados, donde cada bloque es el resultado de aplicar la operación RSA al bloque original.
    """

    e, n = public_key
    encrypted_blocks = []
    
    # Cifrado de cada bloque
    for block in blocks:
        
        encrypted_block = pow(int(block), e, n)
        
        encrypted_blocks.append(encrypted_block)
    
    return encrypted_blocks

def rsadecipher(blocks, private_key):
    """
    Descifra una lista de bloques numéricos usando la clave privada (n, d) del algoritmo RSA.
    
    Args:
    - blocks (list of int): Lista de bloques cifrados a descifrar. Cada bloque debe ser un número entero que representa un fragmento cifrado del mensaje original.
    - private_key (tuple): Tupla (n, d) que representa la clave privada en el sistema RSA.
        - d (int): El exponente privado, que es el inverso modular de e con respecto a φ(n).
        - n (int): El módulo, el cual es el producto de dos números primos grandes p y q (igual que en la clave pública).
        
    
    Returns:
    - list of int: Lista de bloques descifrados, donde cada bloque es el resultado de aplicar la operación RSA al bloque cifrado.
    """

    d, n = private_key
    decrypted_blocks = []
    
    # Descifrado de cada bloque
    for block in blocks:

        decrypted_block = pow(block, d, n)
        if decrypted_block == 0:
            decrypted_block = "000"

        decrypted_blocks.append(decrypted_block)
    
    return decrypted_blocks

'''
# Testing. Ejemplo de claves públicas y privadas.
public_key = (17, 3233)  # (e, n)
private_key = (2753, 3233 )  # (d, n)

# Bloques a cifrar.
blocks = [123, 456, 789]

# Cifrado.
encrypted_blocks = rsacipher(blocks, public_key)
print("Bloques cifrados:", encrypted_blocks)

# Descifrado.
decrypted_blocks = rsadecipher(encrypted_blocks, private_key)
print("Bloques descifrados:", decrypted_blocks)
'''