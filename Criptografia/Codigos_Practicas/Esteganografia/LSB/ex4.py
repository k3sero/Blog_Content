"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""
from PIL import Image
from ex2 import * 

def LSBcomplexcypher(image_path, text, output_image, s):
    """
    Oculta un mensaje en una imagen en blanco y negro utilizando un salto de s píxeles.
    
    Parámetros:
        image_path (str): Ruta de la imagen original en blanco y negro en la que se desea ocultar el mensaje.
        text (str): El mensaje que se quiere ocultar. Este mensaje se convierte a su representación en bits (ASCII).
        output_image (str): Ruta donde se guardará la imagen con el mensaje oculto.
        s (int): El salto de píxeles para ocultar cada bit del mensaje (por ejemplo, 3 para saltar 3 píxeles entre cada bit).
        
    Excepciones:
        ValueError: Si la imagen no tiene suficiente espacio para ocultar el mensaje con el salto s.
    
    Retorna:
        None: La función guarda la imagen con el mensaje oculto en el archivo especificado por output_image.
    """
    
    # Convertimos el mensaje a bits.
    bits = text2bits(text)
    msg_len = len(bits)
    
    # Abrir la imagen y convertirla a escala de grises.
    img = Image.open(image_path).convert('L')
    pixels = list(img.getdata()) 
    
    # Comprobar si la imagen tiene suficiente espacio para ocultar el mensaje con el salto s.
    if s * msg_len > len(pixels):
        raise ValueError("\n[!] No hay suficiente espacio en la imagen para ocultar el mensaje con el salto de píxeles dado.")
    
    # Copiamos los píxeles originales para modificar solo los necesarios.
    new_pixels = pixels.copy()  
    
    # Iterar sobre los bits del mensaje y colocarlos en los píxeles correspondientes (con salto de s).
    for i, bit in enumerate(bits):
        pixel_index = (i + 1) * s - 1  # Índice del píxel donde se colocará el bit.
        new_pixels[pixel_index] = (new_pixels[pixel_index] & ~1) | int(bit)  # Modificar el LSB.
    
    # Colocamos los nuevos píxeles en la imagen y la guardamos.
    img.putdata(new_pixels)
    img.save(output_image)

    print(f"\n[+] Mensaje oculto en {output_image}")


def LSBcomplexdecypher(image_input, secret_len, s):
    """
    Extrae un mensaje oculto en una imagen en blanco y negro utilizando un salto de s píxeles.

    Parámetros:
        image_input (str): Ruta de la imagen de entrada que contiene el mensaje oculto en los píxeles con salto de s.
        secret_len (int): Longitud del mensaje oculto (en número de bits), que debe coincidir con la cantidad de píxeles modificados en la imagen.
        s (int): El salto de píxeles para extraer cada bit del mensaje.
        
    Retorna:
        str: El mensaje oculto extraído de la imagen, convertido de vuelta a texto.
    
    Excepciones:
        ValueError: Si la longitud del mensaje (secret_len) es mayor que el número de píxeles modificados en la imagen.
    """

    # Abrimos la imagen y la convertimos a escala de grises (blanco y negro).
    img = Image.open(image_input).convert('L')
    pixels = list(img.getdata())
    
    # Verificar si la longitud del mensaje es válida (que no exceda el número de píxeles disponibles).
    if secret_len > len(pixels) // s:
        raise ValueError("\n[!] La longitud del mensaje es mayor que el número de píxeles modificados en la imagen.")
    
    # Extraer los bits menos significativos (LSB) de los píxeles con salto de s.
    bits = ''.join(str(pixels[(i + 1) * s - 1] & 1) for i in range(secret_len))
    
    # Convertir los bits extraídos de nuevo a texto.
    return bits2text(bits)

'''
# Testing. Ejemplos
# Incrustar el mensaje.
input_image = "imagen.png"
output_image = "imagen_codificada.png"
s = 89 # Salto de pixeles.

secret = "Est3 e5 Un M3ns4j3 4lt4m43nte Secret0!"
print(f"[!] Este es el mensaje a ocultar: {secret}")
secret_len = len(text2bits(secret))

LSBcomplexcypher(input_image, secret, output_image, s)

# Recuperar el mensaje.
secret_message = LSBcomplexdecypher(output_image, secret_len, s)
print("\n[+] Mensaje recuperado:", secret_message)
'''