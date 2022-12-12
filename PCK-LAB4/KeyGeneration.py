import random

import Crypto.Util.number as number


class KeyGeneration:
    def __init__(self):
        self.p = number.getPrime(8)
        self.q = number.getPrime(8)

    def generate_public_key(self) -> int:
        return self.p * self.q

    def generate_private_key(self) -> tuple:
        return self.p, self.q
