from PIL import Image

def bits_a_ascii(bits):
    bloques = [bits[i:i+8] for i in range(0, len(bits), 8)]
    
    caracteres = [chr(int(bloque, 2)) for bloque in bloques]
    
    cadena_ascii = ''.join(caracteres)
    
    return cadena_ascii

original_image = Image.open("original.png")
beauty_image = Image.open("beauty.png")
original_matrix = original_image.load()
beauty_matrix = beauty_image.load()

new_image = Image.new("RGB", (original_image.size[0], original_image.size[1]))

size = original_image.size[0] * original_image.size[1]

a = 0
b = 1
c = 1
chain_result = ""
position = (0,0)
cont = 1

for i in range (0, 30*8):

    position = ((a % size) // new_image.size[0], (a % size) % new_image.size[1])
    original_pixel = (original_matrix[position[0], (position[1])][2])
    beauty_pixel = (beauty_matrix[(position[0]), position[1]][2])

    if original_pixel != beauty_pixel:

        bit_result = 1
    elif beauty_pixel == 255: 
        bit_result = "x"
    else: 
        bit_result = 0

    if cont % 8 == 0:
        bit_result =str(bit_result) + " "

    chain_result += str(bit_result) 

    a = b
    b = c
    c = a + b
    cont += 1

print("Esta es la flag en binario:", chain_result)

original_image.close()
beauty_image.close()