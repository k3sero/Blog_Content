import pyModeS as pms

# Archivo de entrada y salida
archivo_entrada = "captura.txt"
archivo_salida = "resultado_adsb.txt"

def procesar_mensaje(msg):
    msg = msg.strip().strip('*').strip(';')
    
    if len(msg) != 28 or not msg.startswith("8D"):
        return None  # No es un mensaje ADS-B de 112 bits

    icao = pms.adsb.icao(msg)
    tc = pms.adsb.typecode(msg)

    resultado = {
        "raw": msg,
        "icao": icao,
        "typecode": tc,
    }

    if 1 <= tc <= 4:
        resultado["tipo"] = "Identificación"
        resultado["callsign"] = pms.adsb.callsign(msg)

    elif 9 <= tc <= 18:
        resultado["tipo"] = "Posición (Airborne)"
        resultado["altitud"] = pms.adsb.altitude(msg)
        resultado["lat/lon"] = "Codificado (CPR, requiere más de 1 msg)"

    elif tc == 19:
        resultado["tipo"] = "Velocidad"
        vs = pms.adsb.velocity(msg)
        if vs:
            resultado["velocidad"] = f"{vs[0]} knots"
            resultado["rumbo"] = f"{vs[1]}°"
            resultado["ascenso/descenso"] = f"{vs[2]} ft/min"

    else:
        resultado["tipo"] = "Otro"

    return resultado

def main():
    resultados = []

    with open(archivo_entrada, "r") as f:
        lineas = f.readlines()

    for linea in lineas:
        datos = procesar_mensaje(linea)
        if datos:
            resultados.append(datos)

    # Escribir en archivo
    with open(archivo_salida, "w") as out:
        for datos in resultados:
            out.write("-" * 40 + "\n")
            for k, v in datos.items():
                out.write(f"{k}: {v}\n")

    print(f"\n✅ Resultados guardados en '{archivo_salida}'")

if __name__ == "__main__":
    main()
