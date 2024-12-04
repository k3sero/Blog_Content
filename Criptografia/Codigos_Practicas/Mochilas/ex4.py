"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funcion de cryptoanálisis del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""

from ex1 import *
from ex2 import *
from ex3 import * 

import time

def cryptoanalysis(b, m):
    """
    Criptoanálisis de la mochila de Merkle-Hellman utilizando el ataque de Shamir y Zippel.
    Este método buscará la mochila supercreciente en distintos rangos.
    
    Parámetros:
        b : list of int
            La clave pública de la mochila difícil (b1, b2, ..., bn).
        m : int
            El módulo de la mochila difícil.
    
    Retorna:
        list of int
            La mochila supercreciente generada a partir del ataque.
    """

    print(f"\n[+] Iniciando criptoanálisis de Shamir y Zippel...\n")

    start_time = time.time()  # Iniciar medición del tiempo.

    n = len(b)  # Número de elementos en la clave pública.
    b1, b2 = b[0], b[1]

    # Paso 1: Calcular b2^(-1) mod m.
    b2_inv = invmod(b2, m)

    if b2_inv is None:
        print("[!] Error: No existe el inverso de b2 en el módulo m.")
        return None

    # Paso 2: Calcular q = b1 * b2^(-1) mod m.
    q = (b1 * b2_inv) % m

    # Paso 3: Generar los primeros {q, 2q, ..., (2^n+1)* q mod m}.
    multiples_q = [(q * i) % m for i in range(1, 2 ** (n + 1) + 1)]
    multiples_q = [x for x in multiples_q if x != 0]  # Filtrar los ceros

    # Criptoanálisis iterativo.
    rango_inicial = 1  # El rango inicial de búsqueda de q.
    rango_final = 2 ** (n + 1)  # El rango final.
    while multiples_q:
        print(f"[!] Intentando con el rango [{rango_inicial}, {rango_final}]...")

        # Empezar medición del tiempo para este rango.
        rango_start_time = time.time()

        # Paso 4: Seleccionar el valor más pequeño como candidato para a1.
        candidate_a1 = min(multiples_q)

        # Paso 5: Calcular w = b1 * a1^(-1) mod m.
        a1_inv = invmod(candidate_a1, m)

        if a1_inv is None:
            print(f"[!] Inverso de {candidate_a1} no encontrado. Continuando con el siguiente.")
            multiples_q.remove(candidate_a1)
            continue

        w = (b1 * a1_inv) % m

        # Calculamos el inverso de w.
        w_inv = invmod(w, m)

        # Paso 6: Calcular los elementos de la mochila supercreciente a_i.
        a = [(w_inv * b_i) % m for b_i in b]

        # Verificar si la mochila es supercreciente.
        if knapsack(a):
            # Mochila supercreciente encontrada.
            print(f"\n[+] Tiempo requerido en este rango: {time.time() - rango_start_time:.2f} segundos")
            print(f"[+] Mochila supercreciente encontrada: {a}")
            return a

        # Si no se encontró solución, eliminamos el candidato y seguimos.
        multiples_q.remove(candidate_a1)

        # Preguntar al usuario si desea continuar con el siguiente rango.
        if not multiples_q:
            print(f"\n[!] No se ha encontrado solución en este rango.")
            continue_choice = input(f"¿Desea continuar con el siguiente rango? (si/no): ").lower()
            if continue_choice != 'si':
                break
            else:
                rango_inicial = rango_final + 1
                rango_final = rango_inicial * 2
                multiples_q = [(q * i) % m for i in range(rango_inicial, rango_final + 1)]
                multiples_q = [x for x in multiples_q if x != 0]

    print(f"\n[!] Criptoanálisis finalizado. No se encontró solución.")

    return None