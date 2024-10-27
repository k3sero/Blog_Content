F = GF(251)
E = EllipticCurve(F, [73, 42])

P = E.point([26,38])

print(49*P)