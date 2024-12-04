"""
Nombre del archivo: md5.py
Descripción: Este módulo contiene la funcionalidad de crear hashes en MD5 a partir de mensajes.
Autor: Carlos Marín Rodríguez
"""

import struct
import math

def rotar_izquierda(x, n):
    """
    Realiza una rotación circular hacia la izquierda de n bits.

    Parámetros:
    - x: int
        El número entero sobre el cual se realizará la rotación. Se asume que este número está representado 
        en un formato de 32 bits (un número entre 0 y 2^32 - 1).
    - n: int
        El número de bits a rotar hacia la izquierda. Este valor debe estar en el rango de 0 a 31, ya que se 
        trata de una rotación en un entero de 32 bits.

    Retorno:
    - int
        El número resultante después de la rotación circular hacia la izquierda de x por n bits. La operación
        se realiza de manera que se mantenga el valor dentro del rango de 32 bits (0 a 2^32 - 1).
    """

    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def preparar_mensaje(mensaje):
    """
    Prepara el mensaje para cumplir con el formato requerido en el algoritmo.
    
    Parámetros:
    - mensaje: str
        El mensaje que se desea preparar, que se espera como una cadena de texto.

    Retorno:
    - bytes
        El mensaje preparado en formato de bytes, con los bits añadidos y la longitud del mensaje original.
    """

    mensaje_bytes = mensaje.encode('latin-1')  # Convertir el mensaje en bytes
    longitud_original = len(mensaje_bytes) * 8  # Longitud del mensaje en bits

    # Añadir un bit '1' seguido de ceros.
    mensaje_bytes += b'\x80'  # Añadir un 1 (en binario: 10000000)
    while (len(mensaje_bytes) * 8) % 512 != 448:
        mensaje_bytes += b'\x00'

    # Añadir la longitud original del mensaje como un entero de 64 bits.
    mensaje_bytes += struct.pack('<Q', longitud_original)  # '<Q': Little-endian, entero de 64 bits
    return mensaje_bytes

def funciones_f_g_h_i(x, y, z, i):
    """
    Selecciona y aplica la función correspondiente (F, G, H, I) según la ronda actual en el proceso de hash.
    Cada una de estas funciones opera sobre tres entradas (x, y, z) y devuelve un valor basado en una operación lógica entre ellas. 

    Parámetros:
    - x: int
        El primer valor de entrada para las funciones F, G, H o I. 
    - y: int
        El segundo valor de entrada para las funciones F, G, H o I. 
    - z: int
        El tercer valor de entrada para las funciones F, G, H o I. 
    - i: int
        El índice de la ronda actual. Dependiendo de este valor, se seleccionará una de las funciones.

    Retorno:
    - int
        El resultado de aplicar la función correspondiente a los valores de entrada `x`, `y` y `z`.
    """

    if i < 16:
        return (x & y) | (~x & z)
    elif i < 32:
        return (x & z) | (y & ~z)
    elif i < 48:
        return x ^ y ^ z
    else:
        return y ^ (x | ~z)

def constante_t(i):
    """
    Calcula la constante T(i) como el entero de 32 bits de |sin(i+1)| * 2^32.

    Parámetros:
    - i: int
        El índice de la ronda actual, generalmente de 0 a 63.

    Retorno:
    - int
        La constante T(i) calculada como un entero de 32 bits, resultado de |sin(i + 1)| * 2^32,
        restringido a 32 bits mediante un AND con 0xFFFFFFFF.
    """

    return int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF

def calcular_md5(mensaje):
    """
    Calcula el hash MD5 de un mensaje dado.

    Parámetros:
    - mensaje: str
        El mensaje (o texto) para el cual se desea calcular el hash MD5.

    Retorno:
    - str
        El hash MD5 del mensaje, expresado como una cadena hexadecimal de 32 caracteres.
    """
    # Preparamos el mensaje.
    mensaje_preparado = preparar_mensaje(mensaje)

    # Valores iniciales.
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    # Constantes de rotación aplicadas a cada uno de los 64 pasos de cada bloque de 512.
    rotaciones = [
        7, 12, 17, 22,  # Ronda 1 (i < 16)
        5, 9, 14, 20,   # Ronda 2 (i < 32)
        4, 11, 16, 23,  # Ronda 3 (i < 48)
        6, 10, 15, 21   # Ronda 4 (i < 64)
    ]

    # Procesamos cada bloque de 512 bits.
    for i in range(0, len(mensaje_preparado), 64):

        bloque = mensaje_preparado[i:i+64]

        # Dividimos el bloque en 16 palabras de 32 bits.
        M = list(struct.unpack('<16I', bloque))  
        
        # Inicializamos los valores para este bloque.
        a, b, c, d = A, B, C, D

        # Realizamos las 64 iteraciones.
        for j in range(64):

            if j < 16:
                k = j
                s = rotaciones[j % 4]

            elif j < 32:
                k = (5 * j + 1) % 16
                s = rotaciones[4 + (j % 4)]

            elif j < 48:
                k = (3 * j + 5) % 16
                s = rotaciones[8 + (j % 4)]

            else:
                k = (7 * j) % 16
                s = rotaciones[12 + (j % 4)]

            f = funciones_f_g_h_i(b, c, d, j)
            temp = (a + f + M[k] + constante_t(j)) & 0xFFFFFFFF
            a, b, c, d = d, (b + rotar_izquierda(temp, s)) & 0xFFFFFFFF, b, c

        # Actualizamos los valores iniciales.
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # Combinamos los resultados en el hash final.
    result = ''.join(f'{x:02x}' for x in struct.pack('<4I', A, B, C, D))
    
    return result

'''
# Testing. Ejemplo.
mensaje = "jonatan"
print(f"[+] El mensaje es: {mensaje}")

hash_md5 = calcular_md5(mensaje)
print(f"\n[!] El hash MD5 de '{mensaje}' es: {hash_md5}")
'''