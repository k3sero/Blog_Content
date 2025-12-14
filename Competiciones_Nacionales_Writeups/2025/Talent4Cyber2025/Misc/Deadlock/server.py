import unicodedata


with open("flag.txt", "rb") as file:
    flag = file.read()

banner = '''                                                                                      
                                    #*=                      +*#                                    
                                 ###*                          *###                                 
                             ####*                                *####                             
                          #####             ==        ==             *####                          
                       ##%@@              ++============+*              %@%*#                       
                  #***#%@@%#              *++==========+*               ##%@%##*##                  
               ##****##%%@%%               ++==========++               %%@%%###***##               
            ##****###  **+++++=======     +==============+     ++++==++++++**  ###***###            
          ##***#       *##*****++++++++++++==============+++++***************       ###*##          
         +                           ++***+==============+***++                          ++         
     %####                               *+%+==========+%**                               ###%%     
        ######                         ==*#%*+#@@@@@@*+#%#*=+                         #####%        
          %#**###                 ====+**###%@@@@@@@@@@%###**+====                 ####*#           
             %@@%%####      ====++******   *@@@@@@@@@@@%*   ****++=+====      ####%%@@%             
             ##%%%%%%%#+==++******          %@@@@@@@@@@%          *****+++==+#%%%%%%%%#             
             *#%@%%%%%%%#***               %@@%%%%%%%%@@                ***#%%%%%%%@%##             
             ***#####%%%%%#*=              %#%%%@@@@@%%#%              =*#%%%%%#####***             
              ##*###      #+               %@@%%%%%%%%@@@               +#%     **#*##              
                *****                       %%%@@@%%@%%%                       *****                
                 *****                        %%%%%%%%                         ****                 
                  ****                         %%%%%%                         ****                  
                   ***                                                        **        
                      ____  __  __   ___ ____  _  _ ____  ______  ____ ____  
                      ||    ||\ ||  //   || \\\ \\\// || \\\ | || | ||    || \\\ 
                      ||==  ||\\\|| ((    ||_//  )/  ||_//   ||   ||==  ||  ))
                      ||___ || \||  \\\__ || \\\ //   ||      ||   ||___ ||_//             
'''

print("------------------------------------- ¡ALERTA! DRON BLOQUEADO -------------------------------------")
print(banner)

SECURITY_BLACKLIST = ["abs", "all", "any", "bin", "chr", "dir", "hex", "int", "len", "map", "max", "min", "oct", "ord", "pow", "sum", "str", "set", "zip"]

while True:
    code = input("Introduce la clave de desbloqueo (5 dígitos): ")
    
    try:
        print(f"Nivel de bloqueo del dron: {id(flag)}")
    except Exception as e:
        print("ATAQUE DETECTADO. Abortando...")
        exit()

    if len(code) != 5:
        print("La clave tiene 5 dígitos.")
    else:
        code = unicodedata.normalize('NFKC', code)

        for element in SECURITY_BLACKLIST:
            if element in code:
                print("ATAQUE DETECTADO. Abortando...")
                exit()
        exec(code)