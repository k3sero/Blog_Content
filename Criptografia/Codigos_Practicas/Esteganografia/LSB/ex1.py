"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

from PIL import Image
import numpy as np

def img2grayscalematrix(image_path):
    """
    Convierte una imagen a escala de grises y la devuelve como una matriz 2D.
    
    Parámetros:
        image_path (str): Ruta del archivo de imagen.
    
    Retorna:
        numpy.ndarray: Matriz 2D de la imagen en escala de grises.
    """

    # Cargar la imagen
    image = Image.open(image_path).convert("L")
    
    # Convertir la imagen a escala de grises
    grayscale_image = image.convert("L")
    
    # Obtener los datos de la imagen en escala de grises y convertirla en una matriz NumPy.
    grayscale_matrix = np.array(grayscale_image)
    
    return grayscale_matrix

def img2rgbmatrix(image_path):
    """
    Convierte una imagen a RGB y la devuelve como una matriz 3D.
    
    Parámetros:
        image_path (str): Ruta del archivo de imagen.
    
    Retorna:
        numpy.ndarray: Matriz 3D de la imagen en formato RGB.
    """
    # Cargar la imagen
    image = Image.open(image_path)
    
    # Convertir la imagen a RGB
    rgb_image = image.convert("RGB")
    
    # Obtener los datos de la imagen en formato RGB y convertirla en una matriz NumPy
    rgb_matrix = np.array(rgb_image)
    
    return rgb_matrix

'''
# Testing. Ejemplos
image_path = "imagen.png"
    
# Obtener la matriz en escala de grises
grayscale_matrix = img2grayscalematrix(image_path)
print("[!] Matriz de la imagen en escala de grises:\n")
print(grayscale_matrix)
    
# Obtener la matriz en RGB
rgb_matrix = img2grayscalematrix(image_path)
print("\n[!] Matriz de la imagen en RGB:\n")
print(rgb_matrix)
'''