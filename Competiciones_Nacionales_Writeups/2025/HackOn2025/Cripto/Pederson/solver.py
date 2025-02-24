from pwn import *

def main():
    # Conexión al servidor (ajusta la dirección y puerto según corresponda)
    r = remote("0.cloud.chals.io", 18923)

    # Leer parámetros iniciales del servidor
    r.recvuntil("q = ")
    q = int(r.recvline().strip())
    r.recvuntil("g = ")
    g = int(r.recvline().strip())
    r.recvuntil("h = ")
    h = int(r.recvline().strip())
    r.recvuntil("A = ")
    A = int(r.recvline().strip())

    for round_num in range(5):
        # Leer mensajes del servidor
        r.recvuntil(f"Round {round_num}")  # Esperar al inicio de la ronda

        # Leer el valor de k enviado por el servidor
        r.recvuntil("k = ")
        k = int(r.recvline().strip())

        # Generar s1 y s2 únicos para esta ronda
        s1 = round_num + 1
        s2 = round_num + 1

        # Calcular T = (g^s1 * h^s2) * A^-k mod q
        A_k = pow(A, k, q)
        inv_Ak = pow(A_k, -1, q)
        T_part = (pow(g, s1, q) * pow(h, s2, q)) % q
        T = (T_part * inv_Ak) % q

        # Enviar T al servidor
        r.sendlineafter(">>> ", str(T))

        # Enviar s1 y s2
        r.sendlineafter(">>> ", str(s1))
        r.sendlineafter(">>> ", str(s2))

    # Recibir la flag
    print(r.recvall().decode())

if __name__ == "__main__":
    main()