import random

import Crypto.Util.number as number


class KeyGeneration:
    def __init__(self, p=number.getPrime(8), q=number.getPrime(8)):
        # p and q are prime numbers of 8 bits if they aren't explicitly given
        self.p = p
        self.q = q

    def generate_public_key(self) -> int:
        return self.p * self.q

    def generate_private_key(self) -> tuple:
        return self.p, self.q
