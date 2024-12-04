"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones del ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

def TexttoNumber(string):
    """
    Convierte una cadena de texto en su representación numérica en Z26.

    La función procesa letras (mayúsculas y minúsculas), espacios, y 
    emite advertencias para caracteres no alfabéticos. Las letras se 
    mapean a números en Z26: 'A' -> 0, ..., 'Z' -> 25.

    Parámetros:
        string : str
            Cadena de texto a convertir.

    Retorna:
        list[int]
            Lista de números que representan la cadena en Z26, con:
                - Letras mapeadas a números entre 0 y 25.
                - Espacios representados como -1.
    """

    string = string.upper()
    
    numbers = []
    
    # Convertimos cada carácter en su representación numérica.
    for char in string:
        if char.isalpha():  # Solo procesamos letras.

            if char.isupper():
                num = ord(char) - ord('A')  # Mapeo: 'A' -> 0, ..., 'Z' -> 25

            else:
                num = ord(char) - ord('a')  # Mapeo: 'a' -> 0, ..., 'a' -> 25

            numbers.append(num)

        # Aunque no se pide, de esta manera manejamos más cómodamente los espacios.
        elif char == ' ':
            numbers.append(-1)

        else:
            # Se ignoran caracteres no alfabéticos.
            print(f"[W] Caracter ignorado: {char}")
    
    return numbers