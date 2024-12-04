"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones del ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

def text2bits(text):
    """
    Convierte un texto a su representación en bits (ASCII).
    
    Parámetros:
        text (str): El texto que se quiere convertir a bits.
    
    Retorna:
        str: Representación en bits del texto.
    """

    # Convertir cada carácter del texto a su valor ASCII, luego a binario de 8 bits
    bits = ''.join(format(ord(c), '08b') for c in text)
    return bits

def bits2text(bits):
    """
    Convierte una cadena de bits a su texto original.
    
    Parámetros:
        bits (str): La cadena de bits que se quiere convertir a texto.
    
    Retorna:
        str: El texto correspondiente a los bits.
    """

    # Dividir la cadena de bits en grupos de 8 (un byte por carácter)
    text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
    return text

'''
# Testing. Ejemplos.
text = "Hello world" 
print(f"[!] El texto a convertir es: {text}")
# Convertir texto a bits.
bits = text2bits(text)
print(f"\n[!] Texto a Bits: {bits}")
    
# Convertir los bits de vuelta a texto.
recovered_text = bits2text(bits)
print(f"\n[!] Bits a Texto: {recovered_text}")
'''