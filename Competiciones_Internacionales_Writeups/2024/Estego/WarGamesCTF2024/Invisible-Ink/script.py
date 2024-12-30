from PIL import Image
import os

# Aumentar el límite de píxeles permitido (si realmente confías en la imagen)
Image.MAX_IMAGE_PIXELS = None  # Esto desactiva el límite completamente

# Abrimos el archivo .gif
gif_path = 'challenge.gif'  # Cambia este nombre por la ubicación de tu archivo .gif
output_folder = 'images'

# Creamos la carpeta de salida si no existe
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Abrimos la imagen .gif
gif = Image.open(gif_path)

# Iteramos a través de cada frame del gif y lo guardamos como una imagen separada
frame_count = gif.n_frames
for i in range(frame_count):
    gif.seek(i)
    frame = gif.copy()  # Copiar el frame actual
    frame.save(os.path.join(output_folder, f'frame_{i}.png'))

print(f"Se extrajeron {frame_count} frames y se guardaron en la carpeta '{output_folder}'")
