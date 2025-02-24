from Crypto.Util.number import long_to_bytes
from hashlib import sha512
from z3 import *

MASK64 = (1 << 64) - 1

# Función de rotación para Z3 (se usa en untemper)
def rotl64(x, n):
    return RotateLeft(x, n)

# Función de rotación para enteros (se usa en __call__)
def rotl64_int(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64

inv9 = pow(9, -1, 1 << 64)
inv5 = pow(5, -1, 1 << 64)

def untemper(x):
    # Convertir x a un bit-vector de 64 bits
    x = BitVecVal(x, 64)
    x = (x * inv9) & MASK64
    x = RotateRight(x, 7)  # Rotación inversa a rotl64(x, 7)
    x = (x * inv5) & MASK64
    return simplify(x).as_long()  # Convertir de nuevo a entero

outputs = [
    13212604756760576839566029879790507340621125351650910037096438542986281767798935731815960919847190335319997626490657290703982780531188982755812359825778991287851722231653240101516281221277771687552595606357705667021283245647184176190780371803847239046057899625306709335445492253829904457728963663330232360074002592294748902165490734661754641346105555480845725245401274622849042633220680814862218507825000273496174518135135018296,
    10941254150150025674552873841829377160894872702989189221030375278924020303440766829212501568712317129316625966056943292892254051556591182699583782809766043430039526087782632726822390246237207588223614532129919563546317959123226772171340188871049507419759715801243252593170422974418428462985058137138632654284570886374958625043528751248848999225696572462957490312158113035640608574297096993882606872975815007084967924414642980776,
    15101349666572801938485401280432371477809444483981100057606730238263165151424318566626548931488229895122994206046583802385648294413304175367322953662352599315904063583374091625850491510370325443484473334570074021702629429967091991051778066603994035464123640521499352527048160060494173173666036904182158407134434879411353463525907301113557907096744334931379461289162704385044839685089971009445572331890345614370546943037400147983,
    13342383541948912904739657745633850307061066808554491420342437647156840907474202734010723903582264217743491384126126906186261528960170260592481378655261612977076194385513721691794702104584131178573340233624384858733837689459678253142113892528886104912973772094271490509833087078998828250566430425723306082267268756937078197726277984632313371500970952851404697896276325125638170652585429636027841332778024087695314635287635675733,
    12636229806834250241258615367399065807361433585224380319327082221039501263453353205604056010474585287969305429059979257806627860612598485817264675754852118128230084965081330020085917729023163749382526170463539873149440032710085890969050246185772149152903578407419978590749722355505197313305689658366450442894623670629857776783671952094413125054252154677545972238794873293061464124474598848521323188015310501328407376905710535393
]

hhh = int(sha512(b"What is going on????").hexdigest(), 16)
www = int(sha512(b"-_-").hexdigest(), 16)

eee = []
for output in outputs:
    quotient = output // www
    eee_i = quotient % hhh
    eee.append(eee_i)

s1_values = []
for e in eee:
    part1 = (e >> 128) & MASK64
    part2 = (e >> 64) & MASK64
    part3 = e & MASK64
    s1_values.append(untemper(part1))
    s1_values.append(untemper(part2))
    s1_values.append(untemper(part3))

observed = s1_values[:4]

s = Solver()
s0 = BitVec('s0', 64)
s1 = BitVec('s1', 64)
s2 = BitVec('s2', 64)
s3 = BitVec('s3', 64)

state = (s0, s1, s2, s3)
for i in range(4):
    new_s0, new_s1, new_s2, new_s3 = state
    t = (new_s1 << 17) & MASK64
    s2_prime = new_s2 ^ new_s0
    s3_prime = new_s3 ^ new_s1
    s1_prime = new_s1 ^ s2_prime
    s0_prime = new_s0 ^ s3_prime
    s2_double_prime = s2_prime ^ t
    s3_rot = RotateLeft(s3_prime, 45)
    next_state = (s0_prime, s1_prime, s2_double_prime, s3_rot)
    s.add(new_s1 == observed[i])
    state = next_state

if s.check() == sat:
    m = s.model()
    initial_s0 = m.eval(s0).as_long()
    initial_s1 = m.eval(s1).as_long()
    initial_s2 = m.eval(s2).as_long()
    initial_s3 = m.eval(s3).as_long()
    initial_state = [initial_s0, initial_s1, initial_s2, initial_s3]
    print("Estado inicial encontrado:", initial_state)
else:
    print("No se pudo resolver el estado inicial")
    exit()

class Xoshiro256:
    def __init__(self, s):
        self.s = s.copy()

    def step(self):
        s0, s1, s2, s3 = self.s
        result = s1
        t = (s1 << 17) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        s3 = ((s3 << 45) | (s3 >> (64 - 45))) & MASK64
        self.s = [s0, s1, s2, s3]
        return result

    def __call__(self):
        # Se aplica el tempering usando la versión para enteros
        raw = self.step()
        return ((rotl64_int(raw * 5 & MASK64, 7) * 9) & MASK64)

# Recuperar el estado inicial y avanzar 15 pasos (5 llamadas a otp(), 3 pasos cada una)
rng = Xoshiro256(initial_state)
for _ in range(15):
    rng.step()

# Generación del OTP: se usan los valores temperados llamando a rng() (lo que invoca __call__)
otp_bytes = b''
for _ in range(4):
    key_part = 0
    for __ in range(3):
        key_part = (key_part << 64) | rng()
    otp_bytes += key_part.to_bytes(24, 'big')

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

encrypted_flag = bytes.fromhex("b375f90caac87e919e6f761d8e518e124b62a9658674b09a210503d8844083715f005912fa1e1cfed720c20e9d4f55d3a8eb9b80f0e185c96efce878a15aeb49ebf30eb17de3bd356d465c1e")
flag = xor(encrypted_flag, otp_bytes)
print("Flag:", flag)
