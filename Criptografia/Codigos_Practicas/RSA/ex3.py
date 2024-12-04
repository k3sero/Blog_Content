"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

def text_to_numbers(text):
    """
    Convierte un texto en una representación numérica basada en la posición de las letras en el alfabeto.

    La función elimina los espacios del texto, lo convierte a minúsculas, y asigna a cada letra un número
    de dos dígitos basado en su posición en el alfabeto (a=00, b=01, ..., z=25).

    Parámetros:
        text : str
            El texto que se desea convertir en una representación numérica.

    Retorna:
        str
            Una cadena de números que representa el texto original.
    """

    numbers = []

    # Procesamos cada caracter.
    for char in text.lower():

        if 'a' <= char <= 'z':
            num = ord(char) - ord('a') + 1

            # Nos aseguramos de que tenga 2 digitos.
            numbers.append(f"{num:02}")

    return ''.join(numbers)

def numbers_to_text(numbers):
    """
    Convierte una cadena numérica en texto basado en la posición de las letras en el alfabeto.

    La función toma una cadena de números, donde cada par de dígitos representa la posición de una letra
    en el alfabeto (00=a, 01=b, ..., 25=z), y los traduce de vuelta al texto correspondiente.

    Parámetros:
        numbers : str
            Una cadena numérica donde cada par de dígitos representa una letra del alfabeto.

    Retorna:
        str
            El texto original traducido a partir de la cadena numérica.
    """
    
    text = []

    # Procesamos en bloques de 2.
    for i in range(0, len(numbers), 2):
        num = int(numbers[i:i+2])

        # Convierte el número a letra (01 -> 'a', 02 -> 'b', ...)
        if 1 <= num <= 26:
            text.append(chr(num - 1 + ord('a')))

    return ''.join(text)

'''
# Testing. Ejemplo de uso.
text = "hola"
numbers = text_to_numbers(text)
print(f"Texto a números: {numbers}")

recovered_text = numbers_to_text(numbers)
print(f"Números a texto: {recovered_text}")
'''