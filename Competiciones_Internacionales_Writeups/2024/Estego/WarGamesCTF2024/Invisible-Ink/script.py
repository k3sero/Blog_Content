from PIL import Image, ImageSequence
import os

# Establecer un límite mayor de píxeles para permitir imágenes grandes
Image.MAX_IMAGE_PIXELS = 9331200000  # Establece un nuevo límite de píxeles

gif_path = 'challenge.gif'  # Cambia esto por la ruta de tu archivo GIF
output_folder = 'images'

# Crear la carpeta si no existe
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

try:
    gif = Image.open(gif_path)

    # Redimensionar el GIF a un tamaño más pequeño
    gif.thumbnail((1000, 1000))  # Redimensiona a 1000x1000 píxeles o cualquier tamaño adecuado

    # Usamos ImageSequence para extraer los frames
    for i, frame in enumerate(ImageSequence.Iterator(gif)):
        frame.save(os.path.join(output_folder, f'frame_{i}.png'))

    print(f"Se extrajeron {i+1} frames y se guardaron en la carpeta '{output_folder}'")
except Exception as e:
    print(f"Error al abrir o procesar el archivo: {e}")
