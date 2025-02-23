import secrets

MASK64 = (1 << 64) - 1


def rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


class Xoshiro256estrellaestrella:
    def __init__(self, s: list[int]):
        if len(s) != 4:
            raise ValueError("Invalid state")
        self.s = s

    @staticmethod
    def temper(s1):
        return rotl64(s1 * 5 & MASK64, 7) * 9 & MASK64

    inv9 = pow(9, -1, 1<<64)
    inv5 = pow(5, -1, 1<<64)

    @staticmethod
    def untemper(s1):
        return (rotl64(s1 * Xoshiro256estrellaestrella.inv9 & MASK64, 64 - 7) * Xoshiro256estrellaestrella.inv5 & MASK64)

    def step(self):
        s0, s1, s2, s3 = self.s
        result = s1
        t = (s1 << 17) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        s3 = rotl64(s3, 45)
        self.s = [s0, s1, s2, s3]
        return result

    def __call__(self):
        return self.temper(self.step())