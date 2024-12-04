"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

import numpy as np
from PIL import Image

def es_invertible_mod(A, n):
    """
    Verifica si una matriz 2x2 es invertible en el espacio modular Zn.

    Parámetros:
    - A: np.ndarray
        Matriz cuadrada (2x2) cuyas entradas son enteros.
    - n: int
        Módulo Zn en el que se desea verificar la invertibilidad.

    Retorno:
    - bool
        `True` si la matriz es invertible en Zn.
        `False` si no es invertible en Zn.
    """

    # Calculamos el determinante de A
    det = int(round(np.linalg.det(A)))
    det_mod = det % n
    try:
        # Intentamos calcular el inverso modular
        inv_det = pow(det_mod, -1, n)
        return True
    except ValueError:
        return False

def inversa_mod(A, n):
    """
    Calcula la inversa de una matriz 2x2 en el espacio modular Zn.
    
    Parámetros:
    - A: np.ndarray
        Matriz cuadrada (2x2) cuyas entradas son enteros.
    - n: int
        Módulo Zn en el que se desea calcular la inversa.

    Retorno:
    - np.ndarray
        Matriz inversa de A en Zn. Si no existe una inversa, se generará una excepción.
    """

    # Calculamos determinante de A.
    det = int(round(np.linalg.det(A)))
    det_mod = det % n

    # Calculamos el inverso modular del determinante modular.
    inv_det = pow(det_mod, -1, n)

    # Matriz adjunta escalada
    adj = np.round(np.linalg.inv(A) * det).astype(int)  
    
    # Multiplicamos por el inverso modular y aplicamos módulo
    return (inv_det * adj) % n  

def desordenaimagen(A, imagen, n):
    """
    Desordena una imagen aplicando la transformación definida por la matriz A en el espacio modular Zn.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn. Se utiliza para calcular las nuevas coordenadas
        de los píxeles.
    - imagen: np.ndarray o PIL.Image.Image
        Imagen que se desea desordenar. Puede ser en escala de grises o a color (RGB), en formato NumPy
        o como objeto de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.

    Retorno:
    - imagen_desordenada: np.ndarray
        Imagen desordenada en formato NumPy con las mismas dimensiones que la imagen original.
    """

    if not es_invertible_mod(A, n):
        raise ValueError("\n[!] La matriz A no es invertible en Z{}".format(n))
    
    print(f"\n[+] Desordenando la imagen...")

    # Convertir imagen a formato NumPy. (si es necesario)
    if isinstance(imagen, Image.Image):
        imagen = np.array(imagen)

    filas, columnas = imagen.shape[:2]
    imagen_desordenada = np.zeros_like(imagen)
    
    for i in range(filas):
        for j in range(columnas):

            # Calculamos las nuevas coordenadas
            nueva_pos = np.dot(A, [i, j]) % n
            nueva_i, nueva_j = nueva_pos

            # Mapeamos los píxeles. (Asegurándonos de que estén dentro de los límites)
            nueva_i %= filas
            nueva_j %= columnas
            imagen_desordenada[nueva_i, nueva_j] = imagen[i, j]
    
    return imagen_desordenada

def ordenaimagen(A, imagen_desordenada, n):
    """
    Restaura la imagen original desordenada usando la matriz A y su inversa en el espacio modular Zn.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn. Se utiliza para calcular las coordenadas originales
        de los píxeles.
    - imagen_desordenada: np.ndarray o PIL.Image.Image
        Imagen desordenada que se desea restaurar. Puede estar en formato NumPy (array) o como un objeto
        de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.

    Retorno:
    - imagen_restaurada: np.ndarray
        Imagen restaurada en formato NumPy con las mismas dimensiones que la imagen original.
    """
    
    # Calculamos la inversa.
    A_inv = inversa_mod(A, n)

    print(f"\n[+] Ordenando la imagen...")

    # Convertir imagen a formato NumPy si es necesario
    if isinstance(imagen_desordenada, Image.Image):
        imagen_desordenada = np.array(imagen_desordenada)

    # Inicializamos las dimensiones y la imagen_restaurada.
    filas, columnas = imagen_desordenada.shape[:2]
    imagen_restaurada = np.zeros_like(imagen_desordenada)
    
    for i in range(filas):
        for j in range(columnas):
            # Calculamos las nuevas coordenadas
            nueva_pos = np.dot(A_inv, [i, j]) % n
            nueva_i, nueva_j = nueva_pos
            # Mapeamos los píxeles de vuelta
            nueva_i %= filas
            nueva_j %= columnas
            imagen_restaurada[nueva_i, nueva_j] = imagen_desordenada[i, j]
    
    return imagen_restaurada

'''
# Testing. Ejemplo.
original_image = "imagen.png"
shuffle_image = "imagen_desordenada.png"
ordered_image = "imagen_ordenada.png"

# Matriz de desorden.
A = np.array([[1, 5], [2, 3]])

# Cargar una imagen.
imagen = Image.open(original_image).convert("RGB")
imagen_np = np.array(imagen)

# Obtenemos las dimensiones.
ancho, alto = imagen.size

# Desordenamos la imagen y la guardamos. (Como es cuadrada, utilizamos una dimensión cualquiera)
imagen_desordenada = desordenaimagen(A, imagen_np, ancho)
imagen_desordenada_pil = Image.fromarray(imagen_desordenada)

imagen_desordenada_pil.save(shuffle_image)  
print(f"[+] Imagen desordenada guardada en {shuffle_image}")

# Leer la imagen desordenada para reordenar.
imagen_desordenada_cargada = np.array(Image.open(shuffle_image))

# Restaurar la imagen original. (Realmente, podemos utilizar de nuevo la funcion de desordena (añadir calculo inversa A), ya que al desordenar una imagen desordenada, obtenemos la imagen original)
imagen_restaurada = ordenaimagen(A, imagen_desordenada_cargada, ancho)
imagen_restaurada_pil = Image.fromarray(imagen_restaurada)

imagen_restaurada_pil.save(ordered_image)  
print(f"[+] Imagen ordenada guardada en {ordered_image}")
'''