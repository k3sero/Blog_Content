def lagrange_polynomial_finite_field(x, days, values, p):
    result = 0
    for j in range(len(values)):
        term = values[j]
        for k in range(len(values)):
            if k != j:
                term *= (x - days[k]) * pow((days[j] - days[k]) % p, -1, p)
                term %= p
        result += term
        result %= p
    return result

days = list(range(101))
values = [
    81, 67, 110, 116, 49, 111, 74, 53, 93, 83, 55, 122, 67, 47, 85, 91, 88, 84, 63, 96, 
    59, 87, 46, 99, 93, 126, 62, 65, 76, 55, 48, 116, 79, 106, 45, 54, 102, 100, 65, 93, 
    122, 84, 118, 64, 103, 76, 65, 109, 90, 99, 69, 50, 64, 61, 115, 111, 64, 80, 60, 68, 
    105, 113, 84, 119, 55, 77, 124, 55, 115, 21, 112, 41, 88, 136, 66, 43, 48, 55, 60, 41, 
    43, 103, 118, 19, 99, 34, 118, 73, 97, 74, 7, 78, 60, 48, 123, 125, 119, 0, 36, 123, 22
]
p = 137

valores_predichos = []
for dia_predicho in range(101, 133):
    valor_predicho = lagrange_polynomial_finite_field(dia_predicho, days, values, p)
    valores_predichos.append(valor_predicho)

interpole = ""

for dia, valor in zip(range(101, 133), valores_predichos):
    print("Valor aproximado para DAY({}) en el campo finito es: {}".format(dia, valor))
    interpole += chr(valor) 
    
print(interpole)

#UMASS{1nt3rpr3t_n0r_1nt3rp0l@t3}
