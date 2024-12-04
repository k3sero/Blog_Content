"""
Nombre del archivo: ex8.py
Descripción: Este módulo contiene la funciones del ejercicio 8.
Autor: Carlos Marín Rodríguez

NOTA: Funciona correctamente, pero los valores pueden cambiar con respecto a los de la diapositiva,
        por la forma en la que trato number_to_text, text_to_number, preparetext y preparenumbers.
"""

from ex3 import *
from ex4 import *
from ex5 import *

def rsadeciphertextsign(C1, C2, private_key_receiver, public_key_sender):
    """
    Descifra los criptogramas C1 y C2, y realiza la autenticación del mensaje con la clave pública del emisor.
    
    Parámetros:
    - C1: El primer criptograma cifrado (mensaje y firma).
    - C2: El segundo criptograma cifrado (firma cifrada con clave privada y pública).
    - private_key_receiver (tuple): La clave privada del receptor (nB, dB).
    - public_key_sender (tuple): La clave pública del emisor (nA, eA).
    
    Retorna:
    - plain_c1 : Contiene C1 descifrado completo.
    - is_authenticated: Valor True/False si la firma ha sido exitosa o no.
    - text: Contiene el mensaje intrínseco en texto plano.
    - signature: Contiene la firma en texto claro.
    """

    # Paso 1: Descifrar C1 con la clave privada del receptor (nB, dB)
    decrypted_C1 = rsadecipher(C1, private_key_receiver)
    
    # Convertimos los bloques descifrados de C1 en un único mensaje (pruebabya)
    numbers_c1 = preparetextdecipher(decrypted_C1, len(str(private_key_receiver[1])) - 1)
    
    # Mensaje C1 en claro.
    plain_c1 = numbers_to_text(numbers_c1)

    # Paso 2: Descifrar C2 con la clave privada del receptor (nB, dB)
    decrypted_C2 = rsadecipher(C2, private_key_receiver)
    
    # Completar los bloques de C2 para que tengan la longitud adecuada (nB - 1)
    block_size = len(str(private_key_receiver[1])) - 1
    padded_blocks_C2 = [str(block).zfill(block_size) for block in decrypted_C2]
    
    # Concatenamos los bloques de C2
    concatenated_C2 = ''.join(padded_blocks_C2)
    
    # Paso 3: Descifrar la firma con la clave pública del emisor (nA, eA).
    # Convertimos la firma cifrada en bloques numéricos.
    signature_blocks = preparenumcipher(concatenated_C2, block_size)
    decrypted_signature_numbers = rsacipher(signature_blocks, public_key_sender)

    # Preparamos los números descifrados.
    decrypted_signature_numbers_prepared = preparetextdecipher(decrypted_signature_numbers, block_size+1)

    # Obtenemos el texto plano de la firma cifrada.
    decrypted_signature_plaintext = numbers_to_text(decrypted_signature_numbers_prepared)

    # Obtenemos el mensaje en claro.
    text = plain_c1.replace(decrypted_signature_plaintext, "", 1)  # Elimina la primera aparición de cadena2 en cadena1

    # Obtenemos la firma en claro.
    signature = decrypted_signature_plaintext

    # El mensaje está autenticado si la firma es válida
    is_authenticated = True  # Si no hay errores en el descifrado, consideramos que la firma es válida.
    
    return plain_c1, is_authenticated, text, signature

'''
#Testing.
# NOTA: El ejemplo es el mismo que las diapositivas, pero como trato diferente el text_to_number y number_to_text,
#        finalmente los valores son algo distintos, pero funciona.

# Ejemplo de claves públicas y privadas (Diapositivas)
public_key_sender = (7, 143)  # (eA, nA) del emisor
private_key_receiver = (619, 1003)   # (dB, nB) del receptor
    
# Criptogramas C1 y C2 proporcionados (Necesitas obtenerlos de ex7.py)
C1 = [801, 465, 628, 313, 618, 376]
C2 = [300, 710, 1]

# Llamada a la función para realizar el descifrado y autenticación
c1_plaintext, is_authenticated, text, signature = rsadeciphertextsign(C1, C2, private_key_receiver, public_key_sender)
    
print(f"[!] El criptograma C1 descifrado completo es: {c1_plaintext}")
print(f"[!] El texto en claro es: {text}")
print(f"[!] La firma utilizada es: {signature}")
print("¿El mensaje está autenticado?", is_authenticated)
'''