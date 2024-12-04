"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""

import numpy as np
from PIL import Image
from ex3 import * 

def desordenaimagenite(A, imagen, n, k):
    """
    Desordena una imagen aplicando la transformación definida por  A^k  en el espacio modular  Zn.
    Solicita al usuario un valor k adecuado para calcular A^k.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn.
    - imagen: np.ndarray o PIL.Image.Image
        Imagen que se desea desordenar. Puede ser en escala de grises o a color (RGB), en formato NumPy
        o como objeto de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito  Zn .
    - k: int
        Escalar para obtener A^k.

    Retorno:
    - imagen_desordenada: np.ndarray
        Imagen desordenada en formato NumPy con las mismas dimensiones que la imagen original.
    """

    # Pedimos el valor de k al usuario.
    while True:
        try:
            # Comprobamos el k introducido.
            if k <= 0:
                raise ValueError("[!] k debe ser un entero positivo.")
            # Calculamos  A^k .
            A_k = np.linalg.matrix_power(A, k) % n
            if not es_invertible_mod(A_k, n):
                raise ValueError("[!] La matriz A^k no es invertible en Z{} para el valor de k={}.".format(n, k))
            break
        except ValueError as e:
            print(e)
    
    print(f"\n[+] Usando A^k con k={k}:")
    print(f"[+] Matriz utilizada: ")
    print(A_k)

    print(f"\n[+] Desordenando la imagen...")

    # Convertir imagen a formato NumPy si es necesario.
    if isinstance(imagen, Image.Image):
        imagen = np.array(imagen)

    filas, columnas = imagen.shape[:2]
    imagen_desordenada = np.zeros_like(imagen)
    
    # Desordenamos la imagen usando  A^k.
    for i in range(filas):
        for j in range(columnas):

            nueva_pos = np.dot(A_k, [i, j]) % n
            nueva_i, nueva_j = nueva_pos
            nueva_i %= filas
            nueva_j %= columnas
            imagen_desordenada[nueva_i, nueva_j] = imagen[i, j]
    
    return imagen_desordenada

def ordenaimagenite(A, imagen_desordenada, n, k):
    """
    Restaura la imagen original desordenada usando A^k y su inversa en el espacio modular Zn.
    Solicita al usuario el mismo valor k que se utilizó para desordenar.

    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn.
    - imagen_desordenada: np.ndarray o PIL.Image.Image
        Imagen desordenada que se desea restaurar. Puede estar en formato NumPy (array) o como un objeto
        de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.
    - k: int
        Escalar para obtener A^k.

    Retorno:
    - imagen_restaurada: np.ndarray
        Imagen restaurada en formato NumPy con las mismas dimensiones que la imagen original.
    """
    
    # Pedimos el valor de k al usuario.
    while True:
        try:
            # Comprobamos el valor de k.
            if k <= 0:
                raise ValueError("[!] k debe ser un entero positivo.")

            # Calculamos  A^k  e invertimos la matriz.
            A_k = np.linalg.matrix_power(A, k) % n
            if not es_invertible_mod(A_k, n):
                raise ValueError("[!] La matriz A^k no es invertible en Z{} para el valor de k={}.".format(n, k))
            
            # Calculamos la inversa.
            A_k_inv = inversa_mod(A_k, n)
            break

        except ValueError as e:
            print(e)
    
    print(f"[+] Usando la inversa de A^k con k={k}:")
    print(f"[+] Matriz utilizada:")
    print(A_k_inv)

    print(f"\n[+] Restaurando la imagen...")

    # Convertir imagen a formato NumPy si es necesario.
    if isinstance(imagen_desordenada, Image.Image):
        imagen_desordenada = np.array(imagen_desordenada)

    # Obtenemos las dimensiones e inicializamos la imagen_restaurada.
    filas, columnas = imagen_desordenada.shape[:2]
    imagen_restaurada = np.zeros_like(imagen_desordenada)
    
    # Restauramos la imagen usando la inversa de A^k.
    for i in range(filas):
        for j in range(columnas):

            nueva_pos = np.dot(A_k_inv, [i, j]) % n
            nueva_i, nueva_j = nueva_pos
            nueva_i %= filas
            nueva_j %= columnas
            imagen_restaurada[nueva_i, nueva_j] = imagen_desordenada[i, j]
    
    return imagen_restaurada

'''
# Testing. Ejemplo.
# Definimos una matriz A y un módulo n.
original_image = "imagen.png"
shuffle_image = "imagen_desordenada_ite.png"
restored_image = "imagen_restaurada_ite.png"

# Matriz utilizada.
A = np.array([[1, 2], [3, 5]])

# Obtenemos el valor de k.
k = int(input("[!] Introduce un valor de k (entero positivo): "))

# Cargamos la imagen.
imagen = Image.open(original_image).convert("RGB")

# Obtenemos las dimensiones de la imagen.
ancho, alto = imagen.size


# Desordenamos la imagen.
imagen_desordenada = desordenaimagenite(A, imagen, ancho, k)
Image.fromarray(imagen_desordenada).save(shuffle_image)
print(f"[+] La imagen se desordenó correctamente.")

# Restauramos la imagen.
k = int(input("\n[!] Introduce el valor de k utilizado en la desordenación para ordenar la imagen: "))
imagen_restaurada = ordenaimagenite(A, imagen_desordenada, ancho, k)
Image.fromarray(imagen_restaurada).save(restored_image)
print(f"[+] La imagen se restauró correctamente.")
'''