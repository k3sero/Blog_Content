hex_value = "893bfb5e64002449d089a2c04b04d5d3"

token = int(hex_value, 16)
x2 = token ^ ((1 << 128) - 1)
x2 = x2 << 1

crc = 340282366920938463463374607431768211455
x1 = crc >> 7

m = x1 ^ x2

print(f"Este es el m recuperado es : {m}")