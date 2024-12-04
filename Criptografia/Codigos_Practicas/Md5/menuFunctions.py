"""
Nombre del archivo: menu_md5.py
Descripción: Este módulo contiene funciones relacionadas con el menú MD5.
Autor: Carlos Marín Rodríguez
"""

from os import urandom
from hashlib import md5 # Para el hashing de imagenes y colisonado algo más eficiente.
import hashlib
from md5 import *

# Esta función es redundante y se puede simplificar utilizando únicamente hashear_archivos(), pero para separar los prompts, he decidido dejarla en el código.
def hashear_imagen():
    """
    Calcula el hash MD5 de una imagen (archivo) dado.

    Retorno:
    - str
        El hash MD5 del archivo de imagen, expresado como una cadena hexadecimal de 32 caracteres.
    """
    print(f"\n[INFO] La imagen debe de estar en la misma ruta del script.")
    imagen_path = str(input("[!] Introduce el nombre de la imagen a hashear (con su extensión, p.ej. imagen.png): "))
    
    try:
        # Abrimos la imagen en modo binario.
        with open(imagen_path, 'rb') as f:  
            imagen_data = f.read()
            
            # Usamos hashlib para calcular el MD5.
            md5_hash = hashlib.md5(imagen_data).hexdigest()
            return md5_hash

    except Exception as e:
        print(f"[!] Error al calcular el hash de la imagen: {e}")
        return None

def hashear_archivos():
    """
    Permite al usuario seleccionar un archivo en la misma carpeta para calcular su hash MD5.
    """
    print(f"\n[INFO] El archivo debe de estar en la misma ruta del script.")
    archivo = str(input("[!] Introduce el nombre del archivo a hashear (con su extensión, p.ej. ejemplo.txt): "))
    try:
        with open(archivo, 'rb') as f:
            contenido = f.read().decode("latin-1")

        hash_md5 = calcular_md5(contenido)
        return hash_md5

    except FileNotFoundError:
        print(f"[!] El archivo '{archivo}' no existe.")
    except Exception as e:
        print(f"[!] Error al procesar el archivo: {e}")

def colision():
    """
    Realiza la búsqueda de una colisión de un hash MD5, comparando los primeros n dígitos entre un hash dado y
    hashes generados aleatoriamente. Este método demuestra el concepto de colisiones en hashes, pero es
    computacionalmente ineficiente para valores grandes de n.

    El usuario puede especificar cuántos dígitos iniciales del hash deben coincidir (n). 
    Se recomienda usar valores pequeños para n (menores a 7) para observar resultados prácticos en un tiempo razonable.

    NOTA: Este enfoque utiliza números aleatorios generados por `os.urandom` para buscar colisiones, 
    y no está diseñado para aplicaciones prácticas donde se requiera eficiencia.
    """

    print("──────────────────────────────────────────────────────────────────────────────────────────────────")
    print(f"\n[INFO] La colisión de un hash completo requiere mucho poder de cómputo y tiempo.")
    print(f"[INFO] Este método es funcional pero computacionalmente muy poco eficiente.")
    print(f"\n[INFO] Es por ello que puedes realizar colisión de los n primeros digitos del hash.")
    print(f"[INFO] Puedes introducir n = 32 si quieres la colisión del hash completa, pero no es nada recomendable.")
    print(f"\n[INFO] Para observar el funcionamiento, recomiendo fijar un n menor a 7 .")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────")

    hash = str(input("\n[!] Introduce el hash a colisionar: "))
    n = int(input("[!] Introduce el número de digitos a colisonar: "))

    while(True):

        colision = urandom(32)
        
        # Utilizar md5 de hashlib, para un cómputo más eficiente.
        colision_hash = md5(colision).hexdigest()

        if colision_hash[:n] == hash[:n]:
            print("\n[+] Colisión encontrada!")
            print(f"[+] Hash original es: {hash}")
            print(f"[+] Hash encontrado:  {colision_hash}")
            print(f"[+] Hash pertenece a la palabra: {colision.decode("latin-1")}")
            print(f"[+] Hash encontrado (Bytes): {colision}")