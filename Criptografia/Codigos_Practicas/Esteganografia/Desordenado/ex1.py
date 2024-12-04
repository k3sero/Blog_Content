"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

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

def isinvertible(matrix, n):
    """
    Determina si una matriz 2x2 es invertible en el conjunto Zn.
    
    Parámetros:
        matrix (list of lists): Matriz 2x2 representada como una lista de listas [[a, b], [c, d]].
        n (int): El módulo en el cual determinar la invertibilidad de la matriz.
        
    Retorna:
        bool: True si la matriz es invertible en Zn, False en caso contrario.
    """

    # Extraer los elementos de la matriz 2x2.
    a, b = matrix[0]
    c, d = matrix[1]
    
    # Calcular el determinante de la matriz.
    determinant = (a * d - b * c) % n
    
    # Verificar si el determinante es coprimo con n.
    if algeucl(determinant, n) == 1:
        return True
    else:
        return False

'''
# Testing. Matriz de ejemplo.
matrix = [[1, 2], [3, 4]]
print("[+] La matriz es:")
print(matrix)

# Determinar si la matriz es invertible en Z5
n = 5
print(f"\n[+] Vamos a invertir la matriz en Z{n}")

print(isinvertible(matrix, n))  # Salida: True, ya que el determinante (1*4 - 2*3) = -2 ≡ 3 (mod 5), y gcd(3, 5) = 1.

# Matriz de ejemplo con otro módulo
matrix = [[1, 2], [2, 4]]
print("\n[+] La matriz es:")
print(matrix)

# Determinar si la matriz es invertible en Z6
n = 6
print(f"\n[+] Vamos a invertir la matriz en Z{n}")

print(isinvertible(matrix, n))  # Salida: False, ya que el determinante (1*4 - 2*2) = 0, y gcd(0, 6) = 6.
'''