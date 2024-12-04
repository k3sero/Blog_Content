"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones para el ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

import random
import time
import math

def jacobi(a, b):
    """
    Calcula el símbolo de Jacobi (a/b), que es una generalización del símbolo de Legendre para enteros arbitrarios.
    Utilizado para pruebas de primalidad.

    El símbolo de Jacobi es definido como:
        - 1, si a es un cuadrado perfecto módulo b, o si a y b son congruentes en el caso específico.
        - -1, si no es un cuadrado perfecto módulo b.
        - 0, si a es divisible por b.

    Parámetros:
        a : int
            Un número entero para el cual se desea calcular el símbolo de Jacobi.
        b : int
            Un número entero positivo mayor que 1, sobre el cual se calcula el símbolo de Jacobi.

    Retorna:
        int
            - 1 si (a/b) es 1.
            - -1 si (a/b) es -1.
            - 0 si (a/b) es 0.
    """
    
    # Verificar si b es mayor que 1.
    if b <= 1:
        raise ValueError("b debe ser mayor que 1")
    
    # Modificar 'a' para que esté en el rango [0, b-1] (a % b).
    a = a % b
    
    result = 1
    
    while a != 0:
        
        while a % 2 == 0:

            a = a // 2
            # Si b % 8 es 3 o 5, cambiar el signo del resultado.
            if b % 8 == 3 or b % 8 == 5:
                result = -result
        
        # Intercambiar 'a' y 'b'.
        a, b = b, a
        
        # Si ambos a y b son congruentes a 3 módulo 4, cambiar el signo del resultado.
        if a % 4 == 3 and b % 4 == 3:
            result = -result
        
        # Reducir 'a' en módulo 'b' para continuar el proceso.
        a = a % b
    
    # Si b es igual a 1, el resultado es el valor calculado, que es 1.
    if b == 1:
        return result
    
    # Si b no es igual a 1, el símbolo de Jacobi es 0.
    return 0

def primosolostra(rango_inicio, rango_fin, iteraciones=5):
    """
    Realiza el test de Solovay-Strassen para determinar la probabilidad de que un número sea primo en un rango dado.
    
    El test de Solovay-Strassen es un algoritmo probabilístico, realizando varias iteracionesy devuelve 
    una probabilidad de que el número sea un primo verdadero o un pseudoprimo.
    
    Basado en el símbolo de Jacobi y en la propiedad de que para números primos cumpliendo
        a^((n-1)//2) ≡ (a/n) (mod n) para un número aleatorio a, donde (a/n) es el símbolo de Jacobi.

    Parámetros:
        rango_inicio : int
            El valor de inicio del rango en el que se desean verificar los números primos.
        rango_fin : int
            El valor de fin del rango en el que se desean verificar los números primos.
        iteraciones : int, opcional
            El número de iteraciones a realizar por cada número (por defecto es 5). Un mayor número de iteraciones incrementa la precisión del test.

    Retorna:
        tuple
            - lista de tuplas (n, probabilidad_pseudo_primo), donde n es el número probado y probabilidad_pseudo_primo es la probabilidad de que sea un pseudoprimo.
            - el tiempo total que tomó la ejecución del test.
    """

    start_time = time.time()

    primos_en_rango = []
    
    for n in range(rango_inicio, rango_fin + 1):
        if n <= 1:
            continue  # Números <= 1 no son primos
        
        es_primo = True
        
        for _ in range(iteraciones):
            a = random.randint(2, n - 2)  # Elegir un número aleatorio entre 2 y n-2
            
            # Símbolo de jacobi de a respecto a n.
            jacobi_value = jacobi(a, n)
            
            # Verifica si el símbolo de Jacobi y la condición de Solovay-Strassen se cumplen.
            if jacobi_value == 0 or pow(a, (n - 1) // 2, n) != (jacobi_value % n):
                es_primo = False
                break  # El número no es primo.
        
        # Si el número pasó todas las iteraciones, es probablemente primo.
        if es_primo:
            # Calcular la probabilidad.
            probabilidad_pseudo_primo = 1 / (2 ** iteraciones)
            primos_en_rango.append((n, probabilidad_pseudo_primo))
    
    end_time = time.time()
    tiempo_total = end_time - start_time
    
    return primos_en_rango, tiempo_total

def primoMillerRabin(rango_inicio, rango_fin, iteraciones=5):
    """
    Realiza el test de Miller-Rabin para determinar la probabilidad de que un número sea primo en un rango dado.
    
    El test de Miller-Rabin es un algoritmo probabilístico que verifica si un número es primo con alta probabilidad. 
    
    Si n es primo, para cualquier número aleatorio a (1 < a < n - 1) se cumple que:
        a^d ≡ 1 (mod n) o a^(2^r * d) ≡ -1 (mod n) para algún r.
    
    La complejidad del test es O(k * log(n)), donde k es el número de iteraciones.

    Parámetros:
        rango_inicio : int
            El valor de inicio del rango en el que se desean verificar los números primos.
        rango_fin : int
            El valor de fin del rango en el que se desean verificar los números primos.
        iteraciones : int, opcional
            El número de iteraciones a realizar por cada número (por defecto es 5). Un mayor número de iteraciones incrementa la precisión del test.

    Retorna:
        tuple
            - lista de tuplas (n, probabilidad_pseudo_primo)
            - el tiempo total que tomó la ejecución del test.

    Excepciones:
        Ninguna
    """
    
    start_time = time.time()
    
    primos_en_rango = []
    
    for n in range(rango_inicio, rango_fin + 1):
        if n <= 1:
            continue  # Números <= 1 no son primos.

        if n == 2 or n == 3:
            primos_en_rango.append((n, 1.0))  # Los números 2 y 3 son primos.
            continue
        if n % 2 == 0:
            continue  # Los números pares no son primos.
        
        # Representar n-1 como 2^s * d, donde d es impar.
        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2
        
        es_primo = True
        
        for _ in range(iteraciones):
            a = random.randint(2, n - 2)  # Elige un número aleatorio.
            x = pow(a, d, n)  # Calcula a^d % n.
            if x == 1 or x == n - 1:
                continue
            # Si no es 1 ni n-1, verificar los cuadrados de x.
            for _ in range(s - 1):
                x = pow(x, 2, n)  # Calcular x^2 % n.
                if x == n - 1:
                    break
            else:
                es_primo = False
                break
        
        # Si el número pasó todas las iteraciones, es probablemente primo.
        if es_primo:
            
            probabilidad_pseudo_primo = 1 - (1 / (4 ** iteraciones))
            primos_en_rango.append((n, probabilidad_pseudo_primo))
    
    end_time = time.time()
    tiempo_total = end_time - start_time
    
    return primos_en_rango, tiempo_total


'''
# Testing. Ejemplo de uso.
rango_inicio = 11000
rango_fin = 11100
iteraciones = 10

# Interfaz.
print("\n─────────────────────────────────────────────────────────────────────────────")
print("=============================  Solovay-Strassen  ============================")
print("─────────────────────────────────────────────────────────────────────────────")

primos_solovay, tiempo_solovay = primosolostra(rango_inicio, rango_fin, iteraciones)
print(f"\n[+] Primos encontrados en el rango ({rango_inicio}, {rango_fin})\n")

for primo, probabilidad in primos_solovay:
    print(f"[*] Número: {primo} - Probabilidad de ser pseudoprimo: {probabilidad}")
print(f"\n[+] Tiempo total para el test de Solovay-Strassen: {tiempo_solovay} segundos\n")

print("\n──────────────────────────────────────────────────────────────────────────────")
print("===============================  Miller-Rabin  ===============================")
print("──────────────────────────────────────────────────────────────────────────────")

primos_miller, tiempo_miller = primoMillerRabin(rango_inicio, rango_fin, iteraciones)
print(f"\n[+] Primos encontrados en el rango ({rango_inicio}, {rango_fin})\n")

for primo, probabilidad in primos_miller:
    print(f"[*] Número: {primo} - Probabilidad de ser pseudoprimo: {probabilidad}")
print(f"\n[+] Tiempo total para el test de Miller-Rabin: {tiempo_miller} segundos")
'''