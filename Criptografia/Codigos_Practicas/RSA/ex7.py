"""
Nombre del archivo: ex7.py
Descripción: Este módulo contiene la funciones del ejercicio 7.
Autor: Carlos Marín Rodríguez

NOTA: Funciona correctamente, pero los valores pueden cambiar con respecto a los de la diaopsitiva,
        por la forma en la que trato number_to_text, text_to_number, preparetext y preparenumbers.
"""

from ex3 import *
from ex4 import *
from ex5 import *
from ex6 import *

def rsaciphertextsign(text, public_key_receiver, private_key_sender, signature):
    """
    Realiza la autenticación de firma y genera dos criptogramas.
    
    Parámetros:
    - text (str): El texto a cifrar.
    - public_key_receiver (tuple): La clave pública del receptor (eB, nB).
    - private_key_sender (tuple): La clave privada del emisor (dA, nA).
    - signature (str): La firma del emisor que autentica el mensaje.
    
    Retorna:
    - tuple: Dos criptogramas (C1, C2):
      - C1: Cifrado del texto y la firma con la clave pública del receptor.
      - C2: Cifrado de la firma con la clave privada del emisor y luego con la clave pública del receptor.
    """
    # Paso 1: Cifrar el mensaje y la firma juntos.
    # Convertir el texto y la firma a su forma numérica.
    num_text = text_to_numbers(text)
    num_signature = text_to_numbers(signature)

    # Concatenar el texto y la firma en una sola cadena
    combined = num_text + num_signature
    
    print(combined)

    # Preparar los bloques para el cifrado
    block_size_reciver = len(str(public_key_receiver[1])) - 1  # Usamos el tamaño del módulo del receptor.
    blocks = preparenumcipher(combined, block_size_reciver)
    
    # Cifrar el texto y la firma con la clave pública del receptor.
    C1 = rsacipher(blocks, public_key_receiver)
    
    # Paso 2: Cifrar la firma con la clave privada del emisor y luego con la clave pública del receptor.
    # Primero, ciframos la firma con la clave privada del emisor.
    block_size_sender = len(str(private_key_sender[1])) - 1
    blocks_signature = preparenumcipher(num_signature, block_size_sender)
    signature_private_encrypted = rsacipher(blocks_signature, private_key_sender)

    # Luego, ciframos el resultado con la clave pública del receptor.
    C2 = rsacipher(signature_private_encrypted, public_key_receiver)
    
    return C1, C2

'''
# Testing.
# NOTA: El ejemplo es el mismo que las diapositivas, pero como trato diferente el text_to_number y number_to_text,
#        finalmente los valores son algo distintos, pero funciona.
# Ejemplo de claves públicas y privadas (Diapositivas)
public_key_receiver = (3, 1003)  # (eB, nB) del receptor
private_key_sender = (103, 143)  # (dA, nA) del emisor
text = "prueba"
signature = "bya"

# Llamada a la función para realizar la autenticación de la firma
C1, C2 = rsaciphertextsign(text, public_key_receiver, private_key_sender, signature)
    
print("C1 (texto y firma cifrados con la clave pública del receptor):", C1)
print("C2 (firma cifrada con la clave privada del emisor y luego con la clave pública del receptor):", C2)
'''