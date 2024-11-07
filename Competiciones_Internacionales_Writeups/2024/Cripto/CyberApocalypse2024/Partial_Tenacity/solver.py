from math import sqrt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def load_data():
    with open('output.txt') as f:
        n = int(f.readline().split(' = ')[1])
        ct = bytes.fromhex(f.readline().split(' = ')[1])
        hint_p = int(f.readline().split(' = ')[1])
        hint_q = int(f.readline().split(' = ')[1])
    return n, ct, hint_p, hint_q

def decrypt(p, q, n, ct):
    e = 0x10001
    d = pow(e, -1, (p-1)*(q-1))
    key = RSA.construct((n, e, d))
    flag = PKCS1_OAEP.new(key).decrypt(ct)
    return flag

def create_masks(primelen):
    pmask = ''.join(['1' if i % 2 == 0 else '0' for i in range(primelen)])
    qmask = ''.join(['1' if i % 2 == 1 else '0' for i in range(primelen)])
    return pmask, qmask

def bruteforce_digit(i, n, known_prime, prime_to_check, hint_prime):
    msk = 10**(i+1)
    known_prime = 10**i * (hint_prime % 10) + known_prime
    for d in range(10):
        test_prime = 10**i * d + prime_to_check
        if n % msk == known_prime * test_prime % msk:
            updated_prime_to_check = test_prime			    # correct candidate! update the unknown prime
            updated_hint_prime = hint_prime // 10			# move on to the next digit
            return known_prime, updated_prime_to_check, updated_hint_prime

def factor(n, p, q, hp, hq, pmask, qmask, prime_len):
    for i in range(prime_len):
        if pmask[-(i+1)] == '1': # Conocemos el dígito
            p, q, hp = bruteforce_digit(i, n, p, q, hp)
        else: # No conocemos el dígito
            q, p, hq = bruteforce_digit(i, n, q, p, hq)
            
    assert n == p * q

    return p, q

# Podmemos utilizar la función load_data() --> n, ct, hint_p, hint_q = load_data()
n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct_hex = "7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476"
ct = bytes.fromhex(ct_hex)
hint_p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
hint_q = 15624342005774166525024608067426557093567392652723175301615422384508274269305

prime_len = len(str(int(sqrt(n))))
pmask, qmask = create_masks(prime_len)
p, q = factor(n, 0, 0, hint_p, hint_q, pmask, qmask, prime_len)

flag = decrypt(p, q, n, ct)
print(flag)