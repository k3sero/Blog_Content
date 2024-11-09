from PIL import Image
import numpy as np
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
paths = []

for i in range(400):
    paths.append(os.path.join(script_dir, f"{i}.png"))

def normalize(mat):
    return ((mat - mat.min()) / (mat.max() - mat.min()) * 255).astype(np.uint8)

flag = np.zeros((450, 450), dtype=np.float64)

for path in paths:
    img = Image.open(path)
    arr = np.array(img, dtype=np.float64)
    flag += arr

flag_normalized = normalize(flag)

im = Image.fromarray(flag_normalized)

output_path = os.path.join(script_dir, "flag.png")
im.save(output_path)

print(f"Flag image saved to: {output_path}")