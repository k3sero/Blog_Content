from pyzbar.pyzbar import decode
from PIL import Image
import os

input_dir = "qr_parts"

results = []

for filename in sorted(os.listdir(input_dir)):
    if filename.endswith(".png"):
        path = os.path.join(input_dir, filename)
        img = Image.open(path)
        decoded = decode(img)

        if decoded:
            data = decoded[0].data.decode("utf-8")
            print(f"[{filename}] ➜ {data}")
            results.append((filename, data))
        else:
            print(f"[{filename}] No se pudo decodificar")

with open("qr_results.txt", "w") as f:
    for filename, data in results:
        f.write(f"{filename}: {data}\n")
