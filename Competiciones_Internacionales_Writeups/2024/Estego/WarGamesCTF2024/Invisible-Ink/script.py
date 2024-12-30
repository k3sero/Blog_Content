rt numpy as np
import os

# Ruta del GIF con watermark
gif_path = "watermarked.gif"
output_folder = "images/"
output_masks_folder = "masks/"
output_applied_folder = "applied_masks/"

# Crear carpetas para las imágenes procesadas
os.makedirs(output_folder, exist_ok=True)
os.makedirs(output_masks_folder, exist_ok=True)
os.makedirs(output_applied_folder, exist_ok=True)

# Paso 1: Extraer los fotogramas del GIF
frames = []  # Lista para almacenar los fotogramas como arrays
with Image.open(gif_path) as gif:
    frame_number = 0
    while True:
        # Guardar cada fotograma como PNG
        frame_path = os.path.join(output_folder, f"frame_{frame_number:03d}.png")
        gif.save(frame_path, "PNG")
        print(f"Guardado: {frame_path}")
        
        # Convertir el fotograma a RGB (no a escala de grises)
        frames.append(np.array(gif.convert("RGB")))  # Convertir a formato RGB
        
        frame_number += 1
        try:
            gif.seek(frame_number)  # Avanza al siguiente fotograma
        except EOFError:
            break  # Salir del bucle al final de la animación
