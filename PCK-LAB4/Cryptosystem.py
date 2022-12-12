from KeyGeneration import KeyGeneration


class Cryptosystem:
    def __init__(self):
        keys = KeyGeneration()
        self._private_key = keys.generate_private_key()
        self._public_key = keys.generate_public_key()

    def __encrypt(self, m: int) -> int:
        return m ** 2 % self._public_key

    def __extended_euclidean_algorithm(self, a: int, b: int) -> tuple:
        if b == 0:
            return 1, 0
        else:
            x, y = self.__extended_euclidean_algorithm(b, a % b)
            return y, x - y * (a // b)

    def __decrypt(self, c: int) -> tuple:
        mp = c ** ((self._private_key[0] + 1) // 4) % self._private_key[0]
        mq = c ** ((self._private_key[1] + 1) // 4) % self._private_key[1]
        # TODO: Check if yp and yq are correct
        yp, yq = self.__extended_euclidean_algorithm(self._private_key[0], self._private_key[1])
        r1 = (yp * self._private_key[0] * mq + yq * self._private_key[1] * mp) % (
                    self._private_key[0] * self._private_key[1])
        r2 = (self._private_key[0] * self._private_key[1]) - r1
        r3 = (yp * self._private_key[0] * mq - yq * self._private_key[1] * mp) % (
                    self._private_key[0] * self._private_key[1])
        r4 = (self._private_key[0] * self._private_key[1]) - r3
        return r1, r2, r3, r4

    def encrypt(self, plaintext):
        return None

    def decrypt(self, ciphertext):
        return None
