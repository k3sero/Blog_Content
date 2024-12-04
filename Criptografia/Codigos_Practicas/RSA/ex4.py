"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""

def preparenumcipher(num_str, block_size):
    """
    Divide una cadena numérica en bloques de tamaño block_size.
    Rellena los bloques incompletos con 30 o 0.
    
    Parámetros:
    - num_str (str): Una cadena de caracteres numéricos que será dividida en bloques.
    - block_size (int): El tamaño de los bloques que se desean generar.
    
    Retorna:
    - list: Una lista de bloques de tamaño block_size. Si el último bloque es más pequeño,
      se rellenará con '30' y '0' para completar el tamaño.
    """

    # Dividir en bloques
    blocks = [num_str[i:i+block_size] for i in range(0, len(num_str), block_size)]
    
    # Rellenar el último bloque si es necesario
    if len(blocks[-1]) < block_size:
        remaining_length = block_size - len(blocks[-1])
        padding = '30' * (remaining_length // 2) + '0' * (remaining_length % 2)
        blocks[-1] += padding[:remaining_length] #Añade el padding generado al ultimo bloque
    
    blocks = [int(block) for block in blocks]

    return blocks

def preparetextdecipher(blocks, block_size):
    """
    Combina bloques numéricos en una sola cadena numérica.
    Elimina el relleno (30 o 0) al final.

    Parámetros:
    - blocks (list): Una lista de bloques de texto numérico que deben combinarse.
    - block_size (int): Un entero con el tamaño del bloque.
    
    Retorna:
    - str: Una cadena numérica resultante de combinar los bloques y eliminando el relleno (30 o 0).
    """

    text = ""

    # Unir todos los bloques.
    for block in blocks:

        block = str(block)

        # Si el bloque tiene menos carácteres que el tamaño de bloque.
        if len(block) < block_size:

            # Calcula cuántos carácteres faltan.
            remaining_length = block_size - len(block)

            # Generamos el padding necesario.
            padding = '00' * (remaining_length // 2) + '0' * (remaining_length % 2)

            # Añadimos el padding generado al último bloque.
            block = padding + block

        text+=block
    
    # Elimina los posibles caracteres de relleno (0 y 30 al final)
    while text.endswith("0"):

        #30
        if text.endswith("30"):
            text = text[:-2]

        # 0.    
        elif text.endswith("0"):
            text = text[:-1]

        # 300.
        elif text.endswith("300"):
            text = text[:-3]

    return text

'''
# Testing. Lista Ejemplos.
examples = [
    "070811",             # Caso 1: Sin ceros finales
    "0708110",           # Caso 2: Ceros finales válidos
    "0708113030300",       # Caso 3: Mixto con relleno
    "12300",             # Caso 5: Ceros finales válidos
    "07080"          # Caso 6: Datos válidos con ceros de relleno
]
n = 7073
block_size = len(str(n))-1

for num_str in examples:
    print(f"\nTexto numérico original: {num_str}")
    blocks = preparenumcipher(num_str, block_size)
    print(f"Bloques preparados: {blocks}")
    combined = preparetextdecipher(blocks, block_size)
    print(f"Cadena recuperada: {combined}")
'''