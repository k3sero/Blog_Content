"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

from PIL import Image
from ex2 import *

def LSBsimplecypher(image_input, text, output_image):
    """
    Oculta un mensaje en los primeros píxeles de una imagen utilizando el método de Least Significant Bit (LSB).

    Parámetros:
        image_path (str): Ruta de la imagen original en blanco y negro en la que se desea ocultar el mensaje.
        text (str): El mensaje que se quiere ocultar. Este mensaje se convierte a su representación en bits (ASCII).
        output_image (str): Ruta donde se guardará la imagen con el mensaje oculto.

    Retorna:
        None: La función guarda la imagen con el mensaje oculto en el archivo especificado por `output_image`.

    """
    # Convertir el mensaje a bits.
    bits = text2bits(text)
    msg_len = len(bits)
    
    # Abrir la imagen
    img = Image.open(image_input).convert('L')
    pixels = list(img.getdata())
    
    # Comprobamos si hay suficiente espacio.
    if msg_len > len(pixels):
        raise ValueError("\n[!] No hay espacio en la imagen para ocultar el mensaje.")
    
    new_pixels = []

    # Iterar sobre los píxeles y su índice.
    for i, pixel in enumerate(pixels):

        if i < msg_len:

            # Modificar el bit menos significativo del píxel.
            modified_pixel = (pixel & ~1) | int(bits[i])
            new_pixels.append(modified_pixel)
        else:
            # Si no se necesita modificar, conservamos el píxel original.
            new_pixels.append(pixel)
    
    # Guardamos la imagen resultante.
    img.putdata(new_pixels)
    img.save(output_image)

    print(f"\n[+] Mensaje oculto en {output_image}")

def LSBsimpledecypher(image_input, secret_len):
    """
    Extrae un mensaje oculto en los primeros píxeles de una imagen en blanco y negro utilizando el método de Least Significant Bit (LSB).
    
    Parámetros:
        image_input (str): Ruta de la imagen de entrada que contiene el mensaje oculto en los primeros píxeles.
        secret_len (int): Longitud del mensaje oculto (en número de bits), que debe coincidir con la cantidad de píxeles modificados en la imagen.

    Retorna:
        str: El mensaje oculto extraído de la imagen, convertido de vuelta a texto.
    """

    # Abrimos la imagen.
    img = Image.open(image_input).convert('L')
    pixels = list(img.getdata())
    
    # Extraemos los bits menos significativos.
    bits = ''.join(str(pixel & 1) for pixel in pixels[:secret_len])
    
    return bits2text(bits)

'''
# Testing. Ejemplo.
secret = "Hola mundo"
secret_len = len(text2bits(secret))

image_input = 'imagen.png'
image_output = 'imagen_codificada.png'

# Incrustar el mensaje.
LSBsimplecypher(image_input, secret, image_output)

# Obtención del mensaje.
secret_recovered = LSBsimpledecypher(image_output, secret_len)

print(f"\n[+] Mensaje recuperado: {secret_recovered} ")
'''