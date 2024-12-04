"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones para el ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

import random
from sympy import isprime

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

def keygeneration():
    """
    Genera un par de claves pública y privada utilizando el algoritmo RSA.
    
    1. Elige dos números primos p y q.
    2. Calcula n = p * q.
    3. Calcula la función totiente de Euler: phi(n) = (p - 1) * (q - 1).
    4. Elige un número e tal que sea coprimo con phi(n).
    5. Calcula d, el inverso modular de e mod phi(n).
    
    La clave pública es (e, n) y la clave privada es (d, n).
    
    Retorna:
        tuple: (clave pública, clave privada)
    """
    
    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    print("\n[!] Primos sugeridos:", primes)
    
    p = int(input("\n[!] Ingrese un número primo para p: "))
    q = int(input("[!] Ingrese un número primo para q: "))
    
    # Verificación que p y q sean primos.
    if not (isprime(p) and isprime(q)):
        print("\n[!] Ambos números deben ser primos.")
        return None
    
    n = p * q
    phi = (p - 1) * (q - 1)

    print("\n[!] Introduce un valor para e.")
    print("────────────────────────────────────────────────\n")
    print("1. Usar el primo de Fermat e = 65537.")
    print("2. Elegir e aleatoriamente.")
    print("3. Ingresar un valor de e.")
    print("\n────────────────────────────────────────────────")
    option = int(input("\n[!] Elige una opción: ").strip())
    
    # Opción 1: Primo de Fermat.
    if option == 1:

        e = 65537
        if algeucl(e, phi) != 1:
            print("\n[!] e = 65537 no es coprimo con phi(n). Pruebe otra opción.")
            return None
    
    # Opción 2: e aleatorio.
    elif option == 2:

        e = random.randrange(2, phi)
        while algeucl(e, phi) != 1:
            e = random.randrange(2, phi)
        print(f"\n[+] El número e escogido es {e}")

    # Opción 3: e elegido.
    elif option == 3:

        e = int(input("\n[!] Ingrese un valor de e que sea coprimo con phi(n): "))
        if algeucl(e, phi) != 1:
            print("\n[!] e no es coprimo con phi(n). Intente con otro valor.")
            return None
    
    else:
        print("\n[!] Opción no válida.")
        return None
    
    # Cálculo de d, el inverso modular de e
    d = invmod(e, phi)
    if d is None:
        print("\n[!] No se pudo calcular el inverso modular de e. Pruebe otros valores.")
        return None
    
    # Claves generadas
    public_key = (e, n)
    private_key = (d, n)
    
    print("\n[+] Claves generadas.")
    print("\n[+]Clave pública:", public_key)
    print("[+]Clave privada:", private_key)

    return public_key, private_key

'''
# Testing. Llamada a la función
keygeneration()
'''