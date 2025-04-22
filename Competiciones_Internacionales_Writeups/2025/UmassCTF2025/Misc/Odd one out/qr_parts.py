from PIL import Image
import os

# Cargar imagen original
img = Image.open("OddOneOut.png")

# Parámetros de la cuadrícula (ajústalos si el tamaño cambia)
rows, cols = 8, 8  # 12x12 códigos QR
w, h = img.width // cols, img.height // rows

# Crear carpeta para guardar los QRs
output_dir = "qr_parts"
os.makedirs(output_dir, exist_ok=True)

# Cortar cada QR y guardarlo
for i in range(rows):
    for j in range(cols):
        left = j * w
        upper = i * h
        right = left + w
        lower = upper + h

        qr_img = img.crop((left, upper, right, lower))
        filename = f"{output_dir}/qr_{i:02d}_{j:02d}.png"
        qr_img.save(filename)

print(f"[+] Guardados {rows * cols} códigos QR en la carpeta '{output_dir}'")
