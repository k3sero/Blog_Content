import numpy as np

fs = 1_000_000
baud = 1000
samples_per_symbol = fs // baud

iq = np.fromfile("2025-09-13T13:18:31.iq", dtype=np.float32)
iq = iq[::2] + 1j*iq[1::2]

inst_phase = np.angle(iq[1:] * np.conj(iq[:-1]))
freq_inst = np.unwrap(inst_phase) * fs / (2*np.pi)

bits = []
for i in range(0, len(freq_inst), samples_per_symbol):
    f = np.mean(freq_inst[i:i+samples_per_symbol])
    bits.append(1 if f > 105e3 else 0)  # umbral entre 100k y 110k

bit_str = ''.join(map(str, bits))
msg = ''.join(chr(int(bit_str[i:i+8], 2)) for i in range(0, len(bit_str), 8))
print(msg)
