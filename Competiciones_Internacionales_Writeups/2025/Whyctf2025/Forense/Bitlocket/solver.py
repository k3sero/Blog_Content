import subprocess
import os
import shutil

clave_base = "718894-682847-228371-253055-328559-381458-030668-04"
archivo = "/dev/mapper/loop0p1"
punto_montaje = "/tmp/dislocker_test"

os.makedirs(punto_montaje, exist_ok=True)

for i in range(1000):
    sufijo = f"{i:03d}9"
    clave_completa = f"{clave_base}{sufijo}"
    print(f"Probando: {clave_completa}")

    # Limpiar directorio antes de montar
    for f in os.listdir(punto_montaje):
        path = os.path.join(punto_montaje, f)
        if os.path.isfile(path) or os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)

    resultado = subprocess.run(
        ["sudo", "dislocker", "-V", archivo, f"-p{clave_completa}", "--", punto_montaje],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if resultado.returncode == 0:
        print(f"¡Clave encontrada!: {clave_completa}")
        break
