import random

import Crypto.Util.number as number


class KeyGeneration:
    def __init__(self, k: int, l: int, p=0, q=0):
        # p and q are prime numbers of 8 bits if they aren't explicitly given
        if p == 0 and q == 0:
            # This doesn't really work, but you know, rather than deleting it, we'll just deprecate it.
            raise Exception("Code not working completely. Recommend giving well-defined p and q.")

            while True:
                p: int = number.getPrime(8)
                q: int = number.getPrime(8)
                public_key: int = p * q
                if 27 ** k < public_key < 27 ** l:
                    break
        self.p = p
        self.q = q

    def generate_public_key(self) -> int:
        return self.p * self.q

    def generate_private_key(self) -> tuple:
        return self.p, self.q
