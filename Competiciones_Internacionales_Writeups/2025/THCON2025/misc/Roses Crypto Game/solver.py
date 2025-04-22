def petals_around_the_rose_value(die_face):
    if die_face == 3:
        return 2
    elif die_face == 5:
        return 4
    else:
        return 0

def to_base3_rep(petals_list):
    return [val // 2 for val in petals_list]

def base3_to_int(base3_list):
    return int(''.join(map(str, base3_list)), 3)

def int_to_binary_string(num):
    return bin(num)[2:]

def binary_to_string(binary_string):
    characters = []
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            decimal_value = int(byte, 2)
            characters.append(chr(decimal_value))
    return ''.join(characters)

def decode_message(dice_string):
    petals = [petals_around_the_rose_value(int(c)) for c in dice_string.strip()]
    print(f"[1] Pétalos: {petals}")

    base3_digits = to_base3_rep(petals)
    print(f"[2] Base 3: {''.join(map(str, base3_digits))}")

    base3_number = base3_to_int(base3_digits)
    print(f"[3] Número decimal: {base3_number}")

    binary_str = int_to_binary_string(base3_number)

    # ⚠️ Rellenar binario a múltiplos de 8 bits
    remainder = len(binary_str) % 8
    if remainder != 0:
        padding = 8 - remainder
        binary_str = '0' * padding + binary_str

    print(f"[4] Binario (padded): {binary_str} ({len(binary_str)} bits)")

    message = binary_to_string(binary_str)
    return message


# Cadena original
input_string = "332565656633463553443562123355345335124553335153533361461335554235432333433655553433535565355315145355336333333622345132555545316133135455335"

# Ejecutar
flag = decode_message(input_string)
print(f"[5] Mensaje oculto: {flag}")
