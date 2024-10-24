from Crypto.Cipher import AES
import struct

def get_info():

    with open('suisei.skibidi', 'rb') as file:
        file_content = file.read()

    header = file_content[:58]  
    data_section = file_content[58:] 

    key = header[14:46] 
    iv = header[46:58]   
    tag_length = 16
    ciphertext = data_section[:-tag_length]  
    tag = data_section[-tag_length:]

    width, height = struct.unpack('<II', header[4:12])  
    channels = header[12]  

    print("Los datos de la cabecera .skibidi son los siguientes:")
    print(f"Key: {key}")
    print(f"Iv: {iv}")
    print(f"Tag: {tag}")
    print(f"Ancho: {int(width)}")
    print(f"Alto: {int(height)}")
    print(f"Canales: {int(channels)}")


    decrypt(key, iv, tag, ciphertext) 

def decrypt(key, iv, tag, ciphertext):

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        with open('output2', 'wb') as output_file:
            output_file.write(plaintext)
        print("\nProceso finalizado de correcta")

    except ValueError as e:
        print("Error al desencriptar:", str(e))

get_info()