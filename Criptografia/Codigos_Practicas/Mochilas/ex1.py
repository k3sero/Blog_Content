"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

def letter2ascii(char):
    """
    Convierte un carácter a su valor ASCII.

    Parámetros:
        char : str
            Un único carácter (string de longitud 1) que se desea convertir a su valor ASCII.

    Retorna:
        int
            El valor numérico ASCII correspondiente al carácter ingresado.
    """
    return ord(char)

def ascii2binary(ascii_value, n):
    """
    Convierte un valor ASCII a una lista de bits binarios de longitud n.
    
    Parámetros:
        ascii_value : int
            Valor ASCII a convertir.
        n : int
            Número de bits requeridos para la mochila.
    
    Retorna:
        list[int]
            Lista de bits de longitud n que representan el valor ASCII en binario.
    """
    # Comprobación de longitud.
    if len(char) != 1:
        raise ValueError("El valor debe ser una única letra o un solo carácter.")

    # Convertir a binario y ajustar la longitud al tamaño de la mochila.
    return [int(b) for b in f"{ascii_value:08b}"][-n:]

    # Permitir espacios u otros caracteres (en caso de que se quiera cifrar también caracteres especiales)
    if char == " ":
        return 32  # ASCII para espacio
    elif char.isalpha():  # Si es letra, convertir a mayúscula
        return ord(char.upper())
    else:
        return ord(char)  # Si es otro carácter, devolver su valor ASCII directamente

def ascii2letter(ascii_code):
    """
    Convierte un código ASCII (en el rango de 65 a 90) en una letra mayúscula.

    Esta función toma un valor ASCII correspondiente a una letra mayúscula y devuelve el carácter de esa letra.

    Parámetros:
        ascii_code : int
            Un valor ASCII entre 65 y 90 que representa una letra mayúscula.

    Retorna:
        str
            La letra correspondiente al valor ASCII proporcionado.
    """

    if not (65 <= ascii_code <= 90):
        raise ValueError("El valor ASCII debe corresponder a una letra mayúscula.")

    return chr(ascii_code)

def binary2ascii(binary_representation):
    """
    Convierte una lista de bits en binario a su carácter ASCII correspondiente.

    Esta función toma una lista de bits (0s y 1s) que representan un valor binario y lo convierte a su 
    valor ASCII correspondiente, devolviendo el carácter asociado.

    Parámetros:
        binary_representation : list
            Una lista de 8 elementos (0s y 1s) que representan un valor binario.

    Retorna:
        str
            El carácter ASCII correspondiente al valor binario dado.
    """

    # Convertir la lista de bits a una cadena binaria
    binary_string = ''.join(map(str, binary_representation))
    
    # Convertir la cadena binaria a un valor ASCII
    ascii_value = int(binary_string, 2)
    
    # Convertir el valor ASCII a su carácter correspondiente
    return chr(ascii_value)