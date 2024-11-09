from hashlib import md5

def brute_force_md5(target_hash_prefix):
    for i in range(10000000000):
        hex_iterator = hex(i)[2:]  # Convertir a hexadecimal y eliminar el prefijo '0x'
        hex_iterator = hex_iterator.rjust(8, '0')  # Rellenar con ceros a la izquierda si es necesario

          # Convertir a bytes
        obstacle = bytes.fromhex(hex_iterator)
        
        # Calcular el hash MD5
        hash_md5 = md5(obstacle).hexdigest()  
        
        if hash_md5[:5] == target_hash_prefix:
            return hex_iterator
        
    return None

# Hash MD5 objetivo
target_hash = 'dcaac7f0fc3625dd261480ab5dc370c8'
target_hash_prefix = target_hash[:5]

result = brute_force_md5(target_hash_prefix)

if result:
    print("Cadena encontrada:", result)
    print("Hash MD5:", md5(bytes.fromhex(result)).hexdigest())
else:
    print("No se encontró ninguna cadena que coincida con el prefijo del hash MD5 objetivo.")