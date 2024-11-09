from PIL import Image


original_image = Image.open("original.png")
new_image = Image.new("RGB", (original_image.size[0], original_image.size[1]))
size = original_image.size[0] * original_image.size[1]

original_matrix = original_image.load()
new_matrix = new_image.load()

for i in range(0, new_image.size[0]):
    for j in range(0, new_image.size[1]):
        new_matrix[i, j] = original_matrix[i, j]


bin_flag = ''.join(format(byte, '08b') for byte in open("flag.txt", "rb").read())

a = 0
b = 1
c = 1

for bit in bin_flag:
    position = ((a % size) // new_image.size[0], (a % size) % new_image.size[1])
    new_matrix[position[0], position[1]] = (original_matrix[position[0], position[1]][0], original_matrix[position[0], position[1]][1], original_matrix[position[0], position[1]][2] + int(bit))
    a = b
    b = c
    c = a + b


new_image.save("beauty.png")
original_image.close()
new_image.close()