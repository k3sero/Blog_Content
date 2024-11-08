from binascii import crc32
from pwn import *

def intercambiar_cadenas(cadena):
    # Decodificar la cadena de bytes y dividirla en palabras separadas
    palabras = cadena.decode().strip("b'\n").split(', ')

    # Crear un diccionario para mapear las palabras
    mapeo = {'FIRE': 'ROLL', 'PHREAK': 'DROP', 'GORGE': 'STOP'}

    # Iterar sobre cada palabra y aplicar el mapeo si es necesario
    palabras_intercambiadas = [mapeo.get(palabra, palabra) for palabra in palabras]

    # Unir las palabras intercambiadas de nuevo en una cadena
    cadena_intercambiada = '-'.join(palabras_intercambiadas)

    # Codificar la cadena intercambiada de nuevo en bytes
    cadena_intercambiada_bytes = cadena_intercambiada.encode()

    return cadena_intercambiada_bytes

def intercambiar_cadenas2(cadena):
    # Decodificar la cadena de bytes y extraer lo que sigue después de "What do you do?"
    cadena = cadena.decode()
    indice = cadena.find("What do you do?")
    cadena = cadena[indice+len("What do you do?"):].strip()
    
    # Dividir la cadena en palabras separadas
    palabras = cadena.strip("b'\n").split(', ')

    # Crear un diccionario para mapear las palabras
    mapeo = {'FIRE': 'ROLL', 'PHREAK': 'DROP', 'GORGE': 'STOP'}

    # Iterar sobre cada palabra y aplicar el mapeo si es necesario
    palabras_intercambiadas = [mapeo.get(palabra, palabra) for palabra in palabras]

    # Unir las palabras intercambiadas de nuevo en una cadena
    cadena_intercambiada = '-'.join(palabras_intercambiadas)

    # Codificar la cadena intercambiada de nuevo en bytes
    cadena_intercambiada_bytes = cadena_intercambiada.encode()

    return cadena_intercambiada_bytes
 
r = remote('94.237.61.79',  49263)
print(r.recvuntil(b"Are you ready?"))
r.sendline(b"y")
print(r.recvline())

string = r.recvline()
print("La cadena leida es: ", string)
salida = intercambiar_cadenas(string)
print("la salida es: ", salida)
r.sendline(salida)

for i in range (0,500):
    string = r.recvline()
    print("La cadena leida es: ", string)
    salida = intercambiar_cadenas2(string)
    print("la salida es: ", salida)
    r.sendline(salida)
    print(i)
