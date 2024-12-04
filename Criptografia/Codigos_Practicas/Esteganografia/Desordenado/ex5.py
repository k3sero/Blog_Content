"""
Nombre del archivo: ex5.py
Descripción: Este módulo contiene la funciones del ejercicio 5.
Autor: Carlos Marín Rodríguez
"""

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from ex3 import *
from ex4 import *
from ex5 import *

def desordenaimagenproceso(A, imagen, n, max_k):
    """
    Desordena la imagen de manera iterativa usando la matriz A^k en Zn, mostrando cómo cambia la imagen
    a medida que aumentamos el valor de k.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en Zn. Se utiliza para calcular las nuevas coordenadas de los píxeles.
    - imagen: np.ndarray o PIL.Image.Image
        Imagen que se desea desordenar. Puede ser en escala de grises o RGB, en formato NumPy o como objeto de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.
    - max_k: int
        Número máximo de iteraciones (valores de k) para aplicar. Default es 5.
        
    Retorno:
    - None
    """

    # Convertir imagen a formato NumPy. (si es necesario)
    if isinstance(imagen, Image.Image):
        imagen = np.array(imagen)

    # Crear la figura para mostrar las imágenes.
    plt.figure(figsize=(12, 8))

    # Iterar para aplicar la transformación A^k de 1 a max_k.
    for k in range(1, max_k + 1):

        # Calculamos A^k.
        A_k = np.linalg.matrix_power(A, k) % n
        
        # Desordenamos la imagen con A^k.
        imagen_desordenada = desordenaimagenite(A, imagen, n, k)
        
        # Mostrar la imagen desordenada.
        plt.subplot(1, max_k, k)
        plt.imshow(imagen_desordenada)
        plt.title(f'k = {k}')
        plt.axis('off')  # Desactivar los ejes para mejor visualización

        # Guardamos las imágenes intermedias.
        imagen_desordenada_pil = Image.fromarray(imagen_desordenada)
        imagen_desordenada_pil.save(f"imagen_desordenada_k_{k}.png")

    print(f"\n[!] Para salir de la representación, presione Ctrl + c.")

    plt.tight_layout()
    plt.show()

'''
# Testing. Ejemplo.
original_image = "imagen.png"

# Cargamos la imagen.
imagen = Image.open(original_image).convert("RGB")
imagen_np = np.array(imagen)

# Obtenemos las dimensiones de la imagen.
ancho, alto = imagen.size

# Matriz de desorden.
A = np.array([[1, 2], [3, 5]])

max_k = 5
print(f"[+] Calcularemos el desorden desde k = 1 hasta k = {max_k}")
# Llamamos a la función para mostrar el proceso de desorden con valores de k de 1 a 5.
desordenaimagenproceso(A, imagen_np, ancho, max_k)
'''