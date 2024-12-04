"""
Nombre del archivo: menuMochilas.py
Descripción: Este módulo contiene el menú interactivo para la práctica de mochilas.
Autor: Carlos Marín Rodríguez
"""

from ex1 import *
from ex2 import *
from ex3 import *
from ex4 import *

def menuMochilas():
    """
    Presenta un menú interactivo para gestionar opciones relacionadas con mochilas.

    Opciones del menú:
        1. Menú mochilas normales.
        2. Menú mochilas trampa.
        3. Criptoanálisis Shamir y Zippel.
        4. Salir del menú.

    Esta función permite al usuario seleccionar una opción y ejecuta la correspondiente
    función asociada. Maneja entradas inválidas y errores durante la ejecución.

    Parámetros:
        Ninguno

    Retorna:
        None
    """

    salir = False

    while not salir:
        print("\n─────────────────────────────────────────────────")
        print("================  Menú Mochilas  ================")
        print("─────────────────────────────────────────────────\n")
        print("  1. Menú mochilas.")
        print("  2. Menú mochilas trampa.")
        print("  3. Criptoanálisis Shamir y Zippel.")
        print("\n─────────────────────────────────────────────────")
        print("  4. Salir")
        print("─────────────────────────────────────────────────")
        opcion = input("\n[!] Elige una opción: ").strip()

        try:
            # Opción 1: Menú mochilas normales.
            if opcion == '1':
                opcion1()
                
            # Opción 2: Menú mochilas trampa.
            elif opcion == '2':
                opcion2()
  
            # Opción 3: Criptoanálisis Shamir y Zippel.
            elif opcion == '3':
                opcion3()

            # Opción 4: Salir.
            elif opcion == '4':
                salir = True
                print("\n[!] Saliendo del menú...")
                return    

            else:
                # Opción no válida.
                print("[!] Opción no válida. Por favor, intente de nuevo.")

        except ValueError as ve:
            print(f"[!] Error de entrada: {ve}")
        except Exception as e:
            print(f"[!] Ha ocurrido un error: {e}")

        print()  # \n.

def opcion1():
    """
    Submenú para cifrar o descifrar mensajes utilizando una mochila dada.

    Opciones del submenú:
        1. Cifrar mensaje: Solicita un texto y una mochila para cifrar el mensaje.
        2. Descifrar mensaje: Solicita un mensaje cifrado y la mochila correspondiente para descifrarlo.
        3. Atrás: Regresa al menú principal.

    Parámetros:
        Ninguno

    Retorna:
        None
    """
    print("\n\n────────────────────────────────────────────────")
    print("=============  Funciones Mochilas  =============")
    print("────────────────────────────────────────────────\n")
    print("  1. Cifrar mensaje.")
    print("  2. Descifrar un mensaje.")
    print("\n────────────────────────────────────────────────")
    print("  3. Atrás.")
    print("────────────────────────────────────────────────\n")
    op = input("\n[!] Elige una opción: ").strip()

    try:
        # Opción 1: Cifrar un mensaje con una mochila dada.
        if op == '1':

            s = []
            text = ""

            #Pedimos el texto a el usuario.
            text = input("\n[!] Introduce el texto que quieres cifrar: ").strip()
        
            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila a utilizar (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]

            # Comprobamos la mochila introducida.
            mochila_tipo = knapsack(s)
            if mochila_tipo == 1:
                print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")
            elif mochila_tipo == 0:
                print("\n[+] La mochila no es supercreciente, se procederá con el cifrado igualmente.")
            elif mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return

            # Ciframos el mensaje.
            encrypted = knapsackcipher(text, s)
            print(f"\n[+] El mensaje cifrado es: {encrypted}")

        # Opcion 2: Descfirar mediante una mochila dada.
        if op == '2':

            s = []
            encypted = []

            # Pedir el texto encriptado.
            encrypted_raw = input("\n[!] Introduce el texto encriptado previamente (Ej: 9, 3, 0, 5, 11): ").strip()
            # Convertir la entrada en una lista de enteros.
            encrypted = [int(x) for x in encrypted_raw.split(",")]

            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila a utilizada en el cifrado (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]

            mochila_tipo = knapsack(s)
            if mochila_tipo == 1:
                print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")
            elif mochila_tipo == 0:
                print("\n[+] La mochila no es supercreciente, se procederá con el cifrado igualmente.")
            elif mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return

            # Ciframos el mensaje
            plaintext = knapsackdecipher(encrypted, s)

            print(f"\n[+] El mensaje descifrado es {plaintext}")

        # Opción 3: atrás.
        if op == '3':
            return

    except ValueError as ve:
        print(f"\n[!] Error de entrada: {ve}")
    except Exception as e:
        print(f"\n[!] Ha ocurrido un error: {e}")

def opcion2():
    """
    Submenú para cifrar o descifrar mensajes utilizando mochilas trampa.

    Opciones del submenú:
        1. Cifrar mensaje con mochilas trampa: Solicita un texto y una mochila supercreciente para cifrar el mensaje utilizando una clave pública.
        2. Descifrar mensaje con mochilas trampa: Solicita un mensaje cifrado y la mochila supercreciente correspondiente junto con los parámetros privados para descifrarlo.
        3. Atrás: Regresa al menú principal.

    Parámetros:
        Ninguno

    Retorna:
        None
    """

    print("\n\n────────────────────────────────────────────────")
    print("============  Funciones Mochilas T  ============")
    print("────────────────────────────────────────────────\n")
    print("  1. Cifrar mensaje con mochilas trampa.")
    print("  2. Descifrar un mensaje con mochilas trampa")
    print("\n────────────────────────────────────────────────")
    print("  3. Atrás.")
    print("────────────────────────────────────────────────\n")
    op = input("\n[!] Elige una opción: ").strip()

    try:
        # Opción 1: Cifrar un mensaje con una mochila supercreciente (mochila trampa).
        if op == '1':

            s = []
            text = ""

            #Pedimos el texto a el usuario.
            text = input("\n[!] Introduce el texto que quieres cifrar: ").strip()
        
            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila supercreciente a utilizar (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]

            mochila_tipo = knapsack(s)
            if mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return
            elif mochila_tipo == 0:
                print("\n[!] La mochila no es supercreciente, debe serlo para proceder con el cifrado.")
                return

            print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")

            public_key, (w, m, s_temp) = knapsackpublicandprivate(s)

            # Resultados
            print("\n[+] Clave pública (mochila trampa):", public_key)
            print("[+] Clave privada (w, m, mochila supercreciente):", (w, m, s))

            # Cifrar el mensaje
            encrypted = knapsackcipher(text, public_key)

            print(f"\n[+] El mensaje cifrado es: {encrypted}")


        # Opcion 2: Descfirar mediante una mochila dada.
        if op == '2':

            s = []
            encypted = []

            # Pedir el texto encryptado
            encrypted_raw = input("\n[!] Introduce el texto encriptado previamente (Ej: 9, 3, 0, 5, 11): ").strip()
            # Convertir la entrada en una lista de enteros.
            encrypted = [int(x) for x in encrypted_raw.split(",")]


            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila supercreciente utilizada (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]
            
            m = int(input("\n[!] Introduce el valor del módulo m utilizado: "))
            w = int(input("[!] Introduce el valor de w utilizado: "))

            mochila_tipo = knapsack(s)
            if mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return
            elif mochila_tipo == 0:
                print("\n[!] La mochila no es supercreciente, inserte una nueva mochila.")
                return            

            print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")
            
            # Desciframos el mensaje
            plaintext = knapsackdeciphermh(s, m, w, encrypted)
            print(f"\n[+] El mensaje descifrado es: {plaintext}")

        if op == '3':
            return

    except ValueError as ve:
        print(f"\n[!] Error de entrada: {ve}")
    except Exception as e:
        print(f"\n[!] Ha ocurrido un error: {e}")

def opcion3():
    """
    Realiza el criptoanálisis de Shamir y Zippel con una mochila trampa dada utilizando el valor del módulo proporcionado.

    La función solicita al usuario una mochila trampa y un valor de módulo para intentar romper el cifrado utilizando un algoritmo de criptoanálisis.

    Parámetros:
        Ninguno

    Retorna:
        None
    """

    # Pedir la mochila al usuario.
    mochila_input = input("\n[!] Introduce la mochila trampa a romper (Ej: 3241, 572, 2163, 1256, 3531): ").strip()
    # Convertir la entrada en una lista de enteros.
    b = [int(x) for x in mochila_input.split(",")]

    mochila_tipo = knapsack(b)
    if mochila_tipo == -1:
        print("\n[!] Los elementos introducidos no forman una mochila.")
        return

    m = int(input("\n[!] Introduce el módulo asociado (Ej: 4089): "))

    cryptoanalysis(b, m)

if __name__ == "__main__":
    menuMochilas()