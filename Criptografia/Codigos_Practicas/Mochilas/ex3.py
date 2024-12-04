"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

from sympy import primefactors
import random

from ex1 import *
from ex2 import *

def algeucl(a,b):
    """
    Calcula el Máximo Común Divisor (GCD) de dos números utilizando el algoritmo de Euclides. (P. anterior)

    El algoritmo de Euclides es un método eficiente para encontrar el GCD de dos números enteros.
    La función realiza iteraciones para calcular el residuo de la división de los dos números hasta llegar al GCD.

    Parámetros:
        a : int
            El primer número entero para calcular el GCD.
        
        b : int
            El segundo número entero para calcular el GCD.

    Retorna:
        int
            El Máximo Común Divisor (GCD) de los dos números proporcionados.
    """

    # Comprobacion de errores (Enteros,0 y negativos).
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("[!] Los números deben ser enteros.")
    if a == 0 and b == 0:
        raise ValueError("[!] El GCD de 0 y 0 no está definido.")
    if a < 0 or b < 0:
        print("[W] Uno de los dos números es negativo. Se procdederá con el cálculo.")

    while b > 0:
        
        module = a % b
        a = b
        b = module

    return a

def invmod(p, n):
    """
    Calcula el inverso modular de un número p en un módulo n utilizando el algoritmo extendido de Euclides.
    Es decir, encuentra un número x tal que: p * x ≡ 1 (mod n).

    El algoritmo extendido de Euclides resuelve la ecuación de Bézout: gcd(p, n) = x * p + y * n, donde gcd(p, n) = 1,
    lo que significa que p y n son coprimos y tiene un inverso modular en n.

    Parámetros:
        p : int
            El número del cual se desea encontrar el inverso modular en el módulo n.
        
        n : int
            El módulo en el cual se calculará el inverso de p.

    Retorna:
        int
            El inverso modular de p en el módulo n. Si no existe, lanza una excepción.
    """

    # Comprobaciones (p y n enteros, n entero negativo, p entero positivo, gcd = 1)
    if not isinstance(p, int) or not isinstance(n, int):
        raise ValueError("[!] Los números deben ser enteros.")
    if n < 0:
        n = abs(n)
        print("[W] El valor n es negativo, se consideraŕa positivo.")
    if p < 0:
        print(f"[W] El número p es negativo, se calculará su correspondiente en el anillo.")
        p = p % n
        
    result = algeucl(p,n)
    if algeucl(p,n) != 1:
        return None
    
    # 1 = x * p + b * n (b lo despreciamos)
    
    # Guardamos el valor original de n.
    module = n

    # Inicializamos los coeficientes de la id. de Bezout (a*x + b*y).
    x0, x1 ,y0, y1 = 1, 0, 0, 1

    while n != 0:
        
        q = p // n
        r = p - n * q

        # Actualizamos coeficientes x usando la relación del Algoritmo de Euclides.
        x_temp = x1
        x1 = x0 - q * x1
        x0 = x_temp

        # Actualizamos los coeficientes de y.
        y_temp = y1
        y1 = y0 - q * y1
        y0 = y_temp

        # Preparamos los valores para la próxima iteración.
        p = n
        n = r

    # Si obtenemos un inverso modular negativo, lo calculamos en el anillo.
    x0 = x0 % module

    return x0 # Inverso de p.

def checkwm(w,m,s):
    """
    Verifica si el valor w y el módulo m cumplen las condiciones necesarias para ser utilizados en una mochila trampa.

    - Verifica que w sea invertible módulo m.
    - Comprueba que no existan factores primos comunes entre w y al menos un elemento de s.

    Parámetros:
        w : int
            El número que debe ser invertible en el módulo m.
        
        m : int
            El módulo en el cual se comprobará si w tiene inverso.
        
        s : list of int
            Una lista de elementos con los cuales se comprobará si w tiene factores primos comunes.

    Retorna:
        bool
            True si w es válido para ser utilizado en una mochila trampa, es decir, si:
            - w es invertible módulo m
            - w no tiene factores primos comunes con ningún elemento de s.
            False si alguna de las condiciones no se cumple.
    """

    try:
        # Verifica si w es invertible módulo m.
        invmod(w, m)  # Si no lanza excepción, es invertible.
        
        if commonfactors(w, s):
            return False  # w tiene factores primos comunes con al menos un elemento de s.

        return True  # w es válido.
    except ValueError as e:
        print(f"\n[!] Error en la validación de w: {e}")
        return False

def commonfactors(w,s):
    """
    Comprueba si el número w tiene factores primos comunes con algún elemento de la mochila supercreciente s.

    La función calcula los factores primos de w y los compara con los factores primos de cada elemento de la lista s.
    Si hay factores primos comunes entre w y algún elemento de s, la función devuelve `True`.

    Parámetros:
        w : int
            El número con el cual se comprobarán los factores primos comunes.
        
        s : list of int
            Una lista de elementos de la mochila supercreciente, con los cuales se verifican los factores comunes con w.

    Retorna:
        bool
            True si w tiene factores primos comunes con algún elemento de la lista s.
            False si no tiene factores comunes con ningún elemento de la lista s.
    """

    factors_w = set(primefactors(w))
    
    # Verificar factores primos comunes con cada elemento de s.
    for element in s:
        factors_s = set(primefactors(element))
        if factors_w & factors_s:  # Intersección no vacía significa factores comunes.
            return True
    
    return False

def knapsackpublicandprivate(s):
    """
    Genera un par de claves pública y privada en base a una mochila supercreciente.

    La clave pública es una mochila trampa generada a partir de la mochila supercreciente proporcionada,
    mientras que la clave privada consiste en los parámetros w, m y la mochila supercreciente `s`.

    Parámetros:
        s : list of int
            La mochila supercreciente utilizada para generar las claves.

    Retorna:
        tuple
            Una tupla con la clave pública (mochila trampa) y la clave privada (w, m, mochila supercreciente).
            La clave pública es una lista de números generada a partir de la mochila supercreciente y el valor de w.
            La clave privada contiene los valores de w, m y la mochila supercreciente original.
    """

    # Verificar que s es una mochila supercreciente.
    if knapsack(s) != 1:
        raise ValueError("[!] La mochila proporcionada no es supercreciente.")

    # Calcular el valor mínimo de m (tiene que ser mayor o igual a 2 * a_n).
    an = s[-1]
    m_min = 2 * an

    print(f"\n[!] Introduce un valor del módulo m.")

    while True:
        try:
            m = int(input(f"El valor de m debe ser mayor o igual a {m_min} (2 * {an}): "))
            if m >= m_min:
                break
            print(f"[!] El valor de m debe ser al menos {m_min}.")
        except ValueError:
            print("[!] Introduce un valor entero válido para m.")

    # Buscar w.
    while True:
        try:

            print("\n[!] Introduce el valor de w.\n")
            print("────────────────────────────────────────────────\n")
            print("  1. Buscar W de forma aleatoria.")
            print("  2. Buscar w en un rango dado.")
            print("  3. Introduce un valor en concreto.")
            print("\n────────────────────────────────────────────────\n")
            choice = input("\n[!] Elige una opción: ").strip()
            
            if choice == "1":
                # Generar w de forma aleatoria y comprueba si es buen candidato.
                w = random.randint(2, m - 1)
                while not checkwm(w, m, s):
                    w = random.randint(2, m - 1)

                print(f"\n[+] Valor escogido aleatoriamente: {w}")

            elif choice == "2":
                # Generar w mediante rangos de forma aleatoria.
                lower = int(input("\n[!] Introduce el límite inferior del rango para w: "))
                upper = int(input("[!] Introduce el límite superior del rango para w: "))
                if lower < 2 or upper >= m:
                    print(f"\n[!] El rango debe estar entre 2 y {m-1}.")
                    continue

                if lower >= upper:
                    print("\n [!] El límite inferior debe ser menor que el límite superior.")
                    continue
        
                # Generar un valor aleatorio de w en el rango definido por el usuario.
                w = random.randint(lower, upper)

                # Se generan valores hasta conseguir uno candidato.
                while not checkwm(w, m, s):
                    w = random.randint(lower, upper-1)
                print(f"\n [+] Se ha seleccionado aleatoriamente w = {w} dentro del rango [{lower}, {upper}].")
    
            # Establece un w en concreto.
            elif choice == "3":
                w = int(input("\n[!] Introduce el valor para w: "))

            else:
                print("\n[!] Opción inválida.")
                continue

            # Verificar si w es adecuado
            if checkwm(w, m, s):
                break
            print("\n[!] El valor de w no es válido. Pruebe de nuevo con otro valor.")
        except ValueError:
            print("\n[!] Introduce valores válidos para w y el rango.")

    # Generar la mochila trampa (clave pública).
    public_key = [(w * element) % m for element in s]

    # Retornar claves pública y privada.
    return public_key, (w, m, s)

def knapsackdeciphermh(s, m, w, ciphertext):
    """
    Descifra un mensaje cifrado utilizando el cifrado por mochila supercreciente.

    La función utiliza la mochila supercreciente y los parámetros w (clave privada) y m (módulo) 
    para descifrar un mensaje previamente cifrado con el cifrado de mochila.

    Parámetros:
        s : list of int
            La mochila supercreciente utilizada en el cifrado.
        m : int
            El valor del módulo utilizado para el cifrado.
        w : int
            El valor de la clave privada (w) utilizada en el cifrado.
        ciphertext : list of int
            El mensaje cifrado representado por una lista de números.

    Retorna:
        str
            El mensaje descifrado como una cadena de texto.
    """

    w_inv = invmod(w, m)
    plaintext_bits = []

    # Descifrar cada valor en el criptograma.
    for value in ciphertext:
        # Convertir el valor cifrado al espacio de la mochila supercreciente.
        transformed_value = (value * w_inv) % m

        # Obtener la representación binaria usando la mochila supercreciente.
        binary_representation = [0] * len(s)

        # Resolver la mochila supercreciente para el valor transformado.
        for i in range(len(s) - 1, -1, -1):
            if s[i] <= transformed_value:
                binary_representation[i] = 1
                transformed_value -= s[i]

        # Añadir los bits reconstruidos al texto descifrado.
        plaintext_bits.extend(binary_representation)

        # Agrupar los bits descifrados en bloques de 8 y convertirlos a caracteres ASCII.
        plaintext = ""
        for i in range(0, len(plaintext_bits), 8):
            block = plaintext_bits[i:i+8]  # Tomar un bloque de 8 bits.
            if len(block) < 8:  # Ignorar bloques incompletos.
                break
            ascii_value = int(''.join(map(str, block)), 2)  # Convertir a número decimal.
            plaintext += chr(ascii_value)  # Convertir a carácter ASCII.

    return plaintext