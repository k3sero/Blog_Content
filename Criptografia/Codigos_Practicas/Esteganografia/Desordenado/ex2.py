"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

import numpy as np

def powinverse(A, n):
    """
    Determina el menor p tal que A^p = I (mod n) en Zn.
    
    Parámetros:
    - A (numpy.ndarray): Una matriz cuadrada de enteros que representa la matriz A.
    - n (int): El valor del módulo en el anillo Zn (números enteros módulo n).
    
    Retorna:
    - int: El menor valor de p tal que A^p ≡ I (mod n), donde I es la matriz identidad, o
           None si no se encuentra tal p dentro de un número razonable de iteraciones.
    """

    # Matriz identidad.
    identity = np.eye(A.shape[0], dtype=int) % n

    # Inicializamos la potencia de A para futuras iteraciones.
    power = np.eye(A.shape[0], dtype=int) % n
    
    # Límite de iteraciones.
    max_iterations = n ** 2  

    for p in range(1, max_iterations + 1):

        # Calculamos A^p mod n
        power = np.dot(power, A) % n
        
        # Comparación de la igualdad
        if np.array_equal(power, identity):
            return p

    print("\n[!] No se encontró un p tal que A^p = I en Zn.")
    return 

'''
# Testing. Ejemplo.
A = np.array([[0, 1], [1, 0]]) 
n = 10

p = powinverse(A, n)
print("[+] El valor de p es:", p)
'''