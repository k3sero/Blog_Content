"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""
import numpy as np

def algeucl(a,b):
    """
    Calcula el Máximo Común Divisor (MCD) de dos números enteros 
    utilizando el algoritmo de Euclides.

    Parámetros:
        a : int
            Primer número entero.
        b : int
            Segundo número entero.

    Retorna:
        int
            Máximo Común Divisor de los dos números.
    """

    # Comprobación de errores (Enteros, 0 y valores negativos).
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
    Calcula el inverso modular de un número p en un módulo n 
    utilizando el algoritmo extendido de Euclides. gcd(p, n) = x*p + y*n

    Parámetros:
        p : int
            Número del cual se quiere calcular el inverso modular.
        n : int
            Módulo en el cual se realiza la operación.

    Retorna:
        int
            Inverso modular de p en el módulo n, si existe.
    """

    # Comprobaciones. (p y n enteros, n entero negativo, p entero positivo, gcd = 1)
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
        raise ValueError(f"[!] No existe inverso. Los números {p} y {n} no son comprimos.")
    
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
 
def eulerfun(n):
    """
    Devuelve un listado con los elementos invertibles en el anillo Zn.

    Parámetros:
        n : int
            Módulo del anillo Zn.

    Retorna:
        list
            Lista de enteros que tienen inverso modular en Zn.
    """

    # Comprobaciones de errores.
    if not isinstance(n, int):
        raise ValueError("[!] El número debe ser entero.")
    if n < 0:
        print("[W] El número n es negativo, se considerará positivo]")

    invertibles = []

    for i in range(n):
        try:
            invmod(i, n)
            invertibles.append(i)
        except ValueError:
            pass

    return invertibles 

def invModMatrix(a, n):
    """
    Calcula la inversa de una matriz A en el anillo Zn.

    El cálculo de la inversa se realiza mediante la fórmula:
        A^-1 = (det(A))^-1 * adj(A) mod n

    Parámetros:
        a : list[list[int]]
            Matriz cuadrada cuyos elementos pertenecen a Zn.
        n : int
            Módulo en el que se realiza la operación.

    Retorna:
        list[list[int]]
            Matriz inversa modular de A en Zn.

    Excepciones:
        ValueError
            Si el módulo n no es entero, la matriz A no es cuadrada,
            o no existe inversa modular porque det(A) y n no son coprimos.
    """

    # Comprobamos que el módulo n es un número entero.
    if not isinstance(n, int):
        raise ValueError("[!] El número n debe ser entero.")

    # Comprobar que la Matriz A es cuadrada.
        if any(len(fila) != len(a) for fila in a):
            raise ValueError("[!] La matriz no es cuadrada.")

    # Comprobar que el determinante de A y n sean coprimos.
    det_mod = int(np.linalg.det(a)% n)
    if algeucl(det_mod,n) != 1:
        raise ValueError(f"[!] No existe la matriz inversa en {n} inverso. La matriz a y {n} no son comprimos]")

    # A partir de aquí, para calcular el inverso de una matriz A en Zn, tenemos que calcular la matriz de cofactores junto su traspuesta y multiplicar la adjunta por el inverso  modular del determinante.
    # A^-1 =  1/det(a) * adj(a) mod n
    det_inv = invmod(det_mod, n)

    # Calculamos la matriz de coefactores.
    cofactors = []
    for i in range(len(a)):
        row = []
        for j in range(len(a)):

            # Calculamos el elemento menor asociado a (i, j).
            minor = [row[:j] + row[j + 1:] for z, row in enumerate(a) if z != i]

            # El cofactor es (-1)^(i+j) * determinante del menor
            cofactor = ((-1) ** (i + j)) * np.linalg.det(minor)% n
            row.append(cofactor)

        cofactors.append(row)

    # Calculamos la matriz adjunta sabiendo que es la traspuesta de la matriz de coefactores.
    adjunta =[[cofactors[j][i] for j in range(len(cofactors))] for i in range(len(cofactors[0]))]

    # Por ultimo, calculamos la matriz inversa modular sabiendo que cada elemento de la matriz se multiplica por det_inv y se reduce mod n.
    inversa = [[round((det_inv * adjunta[i][j]) % n) for j in range(len(adjunta))] for i in range(len(adjunta))]

    return inversa