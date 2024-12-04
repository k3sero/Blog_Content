"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3 y el menú para Afín.
Autor: Carlos Marín Rodríguez
"""

from ex1 import *
from ex2 import *

def Afincypher(text, k, d):
    """
    Cifra un texto usando el cifrado Afín: f(x) = k*x + d (mod 26).

    El cifrado Afín mapea cada letra del texto a una nueva letra mediante 
    la fórmula f(x) = k*x + d, donde 'k' es la clave de multiplicación 
    y 'd' es el desplazamiento.

    Parámetros:
        text : str
            Texto a cifrar, que puede contener letras y espacios.
        k : int
            Clave multiplicativa que debe ser coprima con 26.
        d : int
            Clave de desplazamiento.

    Retorna:
        str
            Texto cifrado en base al cifrado Afín.
    
    Excepciones:
        ValueError
            Si 'k' no es coprimo con 26, lo que hace que el cifrado no sea válido.
    """

    n = 26
    list = []
    ciphertext = ""

    # Comprobamos la coprimalidad.
    if algeucl(k, n) != 1:
        raise ValueError("\n[!] El valor de k no es válido. Deber se coprimo con 26.")

    list = TexttoNumber(text)

    for item in list:

        # Aunque no se pide, de esta manera manejamos los espacios (espacio --> -1).
        if item == -1:
            ciphertext += ' '
            continue
        
        y = (k * item + d) % n
        ciphertext += chr(y + ord('A')) 

    return ciphertext

def Afindecypher(ciphertext, k, d):
    """
    Descifra un texto cifrado utilizando el cifrado Afín: x = k^-1 * (y - d) (mod 26).

    Esta función invierte el proceso del cifrado Afín usando la fórmula de descifrado:
    x = k^-1 * (y - d) mod n, donde 'k^-1' es el inverso modular de 'k' en Z26.

    Parámetros:

        ciphertext : str
            Texto cifrado a descifrar, que puede contener letras y espacios.
        k : int
            Clave utilizada en el cifrado, debe ser coprima con 26.
        d : int
            Clave de desplazamiento utilizada en el cifrado.

    Retorna:

        str
            Texto descifrado.
    """

    n = 26
    plaintext = ""

    # Comprobamos nuevamente la coprimalidad de k y n.
    if algeucl(k, n) != 1:
        raise ValueError("\n[!] El valor de k no es válido. Debe ser coprimo con n.")

    k_inv = invmod(k, n)
    cipher_numbers = TexttoNumber(ciphertext)

    for num in cipher_numbers:

        if num == -1:
            plaintext += ' '
            continue
        
        # Aplicamos la fórmula de descifrado: x = k^-1 * (y - d) mod n.
        x = (k_inv * (num -d)) % n
        plaintext += chr(x + ord('A'))

    return plaintext 

def guesskd(y,x):
    """
    Calcula los posibles valores de k (clave multiplicativa) y d (desplazamiento) 
    en el cifrado Afín, dados un carácter cifrado y su correspondiente carácter del texto llano.

    La fórmula utilizada es: y = k * x + d (mod 26), donde y es el carácter cifrado 
    y x es el carácter del texto llano. La función genera todos los posibles pares 
    de k y d que cumplen esta ecuación.

    Parámetros:

        y : str
            Carácter cifrado (texto cifrado).
        x : str
            Carácter del texto llano correspondiente.

    Retorna:

        list[tuple[int, int]]
            Lista de tuplas con los posibles valores de k (clave multiplicativa) 
            y d (desplazamiento) que cumplen la ecuación de cifrado Afín.
    """

    n = 26 

    # Convertimos los caracteres en valores numéricos.
    y_num = TexttoNumber(y)[0]
    x_num = TexttoNumber(x)[0]

    possible_kd = []

    # Iteramos sobre posibles valores de k.
    for k in range(1, n):

        # Comprobamos si k es coprimo con n.
        if algeucl(k, n) == 1:

            # Calculamos d usando la fórmula: d = (y - k * x) mod n
            d = (y_num - k * x_num) % n
            possible_kd.append((k, d))

    return possible_kd

def opcion1():
    """
    Función que cifra un texto mediante el cifrado Afín utilizando un valor de k 
    (clave multiplicativa) y un valor de d (desplazamiento) dados por el usuario.

    Esta función solicita al usuario el texto llano, el valor de k y el valor de d, 
    y luego cifra el texto utilizando el cifrado Afín: f(x) = (k * x + d) mod 26.

    Parámetros:
        Ninguno (los parámetros se obtienen del usuario a través de entradas).

    Retorna:
        Ninguno (imprime el texto cifrado en consola).
    """

    text = input("\n[!] Introduce el texto llano: ")
    k = int(input("[!] Introduce el valor de k (debe ser coprimo con 26, Ej: 25): "))
    d = int(input("[!] Introduce el valor de d (Ej: 3): "))

    if algeucl(k, 26) != 1:
        print("\n[!] El valor de k no es válido. Debe ser coprimo con 26.")
    else:
        ciphertext = Afincypher(text, k, d)
        print(f"\n[+] Texto cifrado: {ciphertext}")


def opcion2():
    """
    Función que descifra un texto cifrado utilizando el cifrado Afín. El usuario puede elegir entre dos opciones:
    1. Descifrar el texto en base a un valor de k (clave multiplicativa) y d (desplazamiento) conocidos.
    2. Descifrar el texto utilizando un enfoque de fuerza bruta, probando todas las combinaciones posibles de k y d.

    Parámetros:
        Ninguno (los parámetros se obtienen del usuario a través de entradas).

    Retorna:
        Ninguno (imprime el texto descifrado o las opciones posibles en consola).
    """

    ciphertext = input("\n[!] Introduce el texto cifrado: ").upper()

    print("\n────────────────────────────────────────────────\n")
    print("  1. Descifrar en base a k y d conocido.")
    print("  2. Descifrar el texto mediante fuerza bruta")
    print("\n────────────────────────────────────────────────")
    print("  3. Atrás")
    print("────────────────────────────────────────────────\n")
    op = input("\n[!] Elige una opción: ").strip()

    try:
        # Opción 1: Descifrar en base a k y d conocido.
        if op == '1':

            k = int(input("\n[!] Introduce el valor de k utilizado anteriormente: "))
            d = int(input("[!] Introduce el valor de d utilizado anteriormente: "))

            if algeucl(k, 26) != 1:
                print("\n[!] El valor de k no es válido. Debe ser coprimo con 26.")
            else:
                plaintext = Afindecypher(ciphertext, k, d)
                print(f"\n[+] Texto descifrado: {plaintext}")

        # Opción 2: Descfirar mediante fuerza bruta.
        if op == '2':

            it = 0
            y = input("\n[!] Introduce la letra del texto cifrada: ").upper()
            x = input("[!] Introduce una posible letra en texto claro correspondiente: ").upper()

            if len(y) != 1 or len(x) != 1 or not y.isalpha() or not x.isalpha():
                print("\n[!] Debes introducir un único carácter alfabético para cada letra.")
            else:
                kd_values = guesskd(y, x)
                print("\n[+] Estos son los posibles textos en claro:\n")
                for k, d in kd_values:
                    it += 1
                    print(f"[Texto {it}]  {Afindecypher(ciphertext, k, d)}")

        # Opción 3: Atrás.
        if op == '3':
            return

    except ValueError as ve:
        print(f"\n[!] Error de entrada: {ve}")
    except Exception as e:
        print(f"\n[!] Ha ocurrido un error: {e}")

def Afincriptoanalisis():
    """
    Función interactiva para realizar un criptoanálisis del cifrado Afín. Permite al usuario:
    1. Cifrar un texto en base a un valor de k y d.
    2. Descifrar un texto a partir de un texto cifrado, usando claves conocidas o mediante fuerza bruta.
    3. Salir del menú.

    Parámetros:
        Ninguno (se obtiene entrada del usuario durante la ejecución).

    Retorna:
        Ninguno (imprime resultados o mensajes según la elección del usuario).

    Excepciones:
        Si ocurre un error durante la entrada o ejecución de las funciones, se muestra un mensaje de error.
    """

    salir = False

    while not salir:
        print("\n─────────────────────────────────────────────────")
        print("=========  Menú de Criptoanálisis Afín  =========")
        print("─────────────────────────────────────────────────\n")
        print("  1. Cifrar texto en base a un k y d")
        print("  2. Descifrar texto a partir del texto cifrado")
        print("\n─────────────────────────────────────────────────")
        print("  3. Salir")
        print("─────────────────────────────────────────────────")
        opcion = input("\n[!] Elige una opción: ").strip()

        try:
            # Opción 1: Cifrar texto.
            if opcion == '1':
                opcion1()
                
            # Opción 2: Descifrar texto.
            elif opcion == '2':
                opcion2()
  
            # Opción 3: Salir.
            elif opcion == '3':
                salir = True
                print("\n[!] Saliendo del menú...")
                return

            else:
                # Opción no válida.
                print("\n[!] Opción no válida. Por favor, intente de nuevo.")

        except ValueError as ve:
            print(f"\n[!] Error de entrada: {ve}")
        except Exception as e:
            print(f"\n[!] Ha ocurrido un error: {e}")

        print()  # \n.

if __name__ == "__main__":
    Afincriptoanalisis()