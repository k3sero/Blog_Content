"""
Nombre del archivo: menu_md5.py
Descripción: Este módulo contiene el menú con opciones dedicadas a MD5.
Autor: Carlos Marín Rodríguez
"""

import struct
import math

from md5 import *
from menuFunctions import *

def menu():
    """
    Muestra un menú de opciones para que el usuario seleccione diferentes funcionalidades relacionadas con hashes MD5.
    El menú incluye opciones para calcular el hash de un mensaje, archivo, imagen, o generar colisiones de hashes.
    """

    while True:

        print("\n─────────────────────────────────────────────────")
        print("===================  Menú MD5  ==================")
        print("─────────────────────────────────────────────────\n")
        print("    1. Realizar el hash de un mensaje.")
        print("    2. Realizar el hash de un archivo de texto.")
        print("    3. Realizar el hash de una imagen.")
        print("    4. Realizar colisiones de hashes.")
        print("\n─────────────────────────────────────────────────")
        print("    5. Salir")
        print("─────────────────────────────────────────────────")
        opcion = input("\n[!] Elige una opción: ").strip()

        # Realizar hash de un mensaje.
        if opcion == '1':
            mensaje = str(input("\n[!] Introduce el mensaje a hashear: "))
            hash_md5 = calcular_md5(mensaje)
            print(f"\n[+] El hash MD5 de '{mensaje}' es: {hash_md5}")
        
        # Realizar hash de un archivo.
        elif opcion == '2':
            hash_md5 = hashear_archivos()
            print(f"\n[+] El hash MD5 del archivo del archivo introducido es: {hash_md5}")
        
        # Realizar hash de una imagen.
        elif opcion == '3':
            hash_md5 = hashear_imagen()
            print(f"\n[+] El hash MD5 del archivo de la imagen es: {hash_md5}")
        
        # Colisión de hashes.
        elif opcion == '4':
            colision()
            break
        
        # Salir del programa.
        elif opcion == '5':
            print("\n[!] Saliendo del programa.")
            break

        else:
            print("[!] Opción no válida. Por favor, selecciona una opción del 1 al 4.")

if __name__ == "__main__":
    menu()