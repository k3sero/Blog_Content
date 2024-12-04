"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones del ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

from itertools import combinations
from ex1 import *

def knapsack(vector):
    """
    Determina el tipo de mochila en base a un vector de enteros.

    - Mochila Supercreciente: Cada elemento del vector es mayor que la suma de los anteriores. (1)
    - Mochila no supercreciente: Es una mochila, pero no cumple el criterio de supercreciente. (0)
    - No es mochila: Contiene elementos negativos o no es un vector con números enteros positivos. (-1)

    Parámetros:
        vector : list
            Una lista de números enteros, que representan los valores de los elementos de la mochila.

    Retorna:
        int
            - 1 si es una mochila supercreciente.
            - 0 si es una mochila pero no supercreciente.
            - -1 si no es una mochila (por contener elementos negativos o no ser un vector con enteros).
    """

    total = 0

    #Verificar si todos los elementos son enteros positivos.
    if not all(isinstance(x, int) and x > 0 for x in vector):
        return -1 # No es una mochila.
    
    # Comprobar si es una mochila.
    for num in vector:

        # Mochila pero no supercreciente.
        if num <= total:
            return 0 
        
        total += num
    
    # Mochila supercreciente.
    return 1

def knapsacksol(s, v):
    """
    Determina si el valor v puede obtenerse mediante una mochila supercreciente s.
    Devuelve los índices de los elementos que forman el valor objetivo v.

    Si la mochila s es supercreciente, utiliza un algoritmo eficiente basado en su propiedad.
    Si la mochila no es supercreciente, utiliza un algoritmo de fuerza bruta.

    Parámetros:
        s : list
            Una lista de enteros positivos que representan los elementos de la mochila.
            Debe ser una mochila, ya sea supercreciente o no.
        
        v : int
            El valor objetivo que se desea obtener con una combinación de los elementos de la mochila.

    Retorna:
        list
            Una lista con los índices de los elementos que suman el valor v, si se puede obtener dicho valor.
            Si no es posible obtener el valor v, devuelve None.
    """

    # Si la mochila es supercreciente, utilizamos su algoritmo.
    if knapsack(s) == 1:

        indices = []
        n = len(s)

        # Bucle for empezando en n-1, acaba en -1 y tiene un paso de -1.
        for i in range(n - 1, -1, -1):

            if s[i] <= v:
                indices.append(i)
                v -= s[i]

        return indices if v == 0 else None

    # Si la mochila no es supercreciente, usamos el algoritmo general.
    n = len(s)

    for r in range(1, n + 1):

        # Generamos con combinations todas las posibles combinaciones.
        for combination in combinations(range(n), r):
            subset_sum = sum(s[i] for i in combination)
            if subset_sum == v:
                return list(combination)

    # Si no se encuentra solución, no se alcanza el valor objetivo.
    return None

def knapsackcipher(text, knapsack):
    """
    Función que cifra un texto utilizando el cifrado por mochilas. 
    Realiza los pasos de conversión a ASCII, agrupación en bloques del tamaño de la mochila y
    realiza el cifrado con la suma ponderada.

    Parámetros:
    - text (str): Texto que se desea cifrar.
    - knapsack (list[int]): Mochila supercreciente utilizada para el cifrado.

    Retorno:
    - list[int]: Lista de números enteros que representan el texto cifrado.
    """

    ciphertext = []
    block_size = len(knapsack)  # Tamaño de los bloques (debe coincidir con el tamaño de la mochila)

    # Convertir cada carácter del texto a su representación ASCII y luego a binario (8 bits).
    binary_text = ''.join(f"{ord(char):08b}" for char in text)
    
    # Dividir el texto binario en bloques del tamaño de la mochila.
    blocks = [binary_text[i:i+block_size] for i in range(0, len(binary_text), block_size)]

    if len(blocks[-1]) < block_size:
        blocks[-1] = blocks[-1].ljust(block_size, '1')  # Como es un bloque corto, se rellena con 1 al final 

    # Cifrar cada bloque utilizando la mochila.
    for block in blocks:
        # Convertir el bloque binario en una lista de bits.
        bits = [int(bit) for bit in block]

        # Realizar la suma ponderada utilizando la mochila.
        cipher_value = sum(k * b for k, b in zip(knapsack, bits))

        # Añadir el valor cifrado a la lista de resultados.
        ciphertext.append(cipher_value)
    
    return ciphertext

def knapsackdecipher(ciphertext, knapsack):
    """
    Función que descifra un texto cifrado utilizando el cifrado por mochilas.

    Parámetros:
    - ciphertext (list[int]): Lista de números enteros que representan el texto cifrado.
    - knapsack (list[int]): Mochila supercreciente utilizada para el cifrado.

    Retorno:
    - plaintext (str): El texto descifrado.
    """

    n = len(knapsack)  # Tamaño de los bloques.
    plaintext_bits = []  # Almacenará todos los bits descifrados.
    plaintext = ""

    for value in ciphertext:
        # Reconstruir el bloque binario a partir del valor cifrado.
        binary_representation = [0] * n  # Inicializar lista binaria de tamaño n.
        for i in range(n - 1, -1, -1):  # Iterar desde el final de la mochila hacia el principio.
            if knapsack[i] <= value:
                binary_representation[i] = 1
                value -= knapsack[i]
        
        # Añadir los bits reconstruidos al texto descifrado.
        plaintext_bits.extend(binary_representation)

    # Agrupar los bits descifrados en bloques de 8 y convertirlos a caracteres ASCII.
    for i in range(0, len(plaintext_bits), 8):
        block = plaintext_bits[i:i+8]  # Tomar un bloque de 8 bits
        if len(block) < 8:  # Ignorar bloques incompletos
            break
        ascii_value = int(''.join(map(str, block)), 2)  # Convertir a número decimal
        plaintext += chr(ascii_value)  # Convertir a carácter ASCII

    return plaintext