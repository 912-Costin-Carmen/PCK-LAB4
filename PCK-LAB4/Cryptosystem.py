import copy

from Alphabet import Alphabet
from KeyGeneration import KeyGeneration


class Cryptosystem:
    def __init__(self, k: int, p: int = 0, q: int = 0):
        self._bit_count_used_for_validation = k

        if p == 0 and q == 0:
            keys = KeyGeneration()
        else:
            keys = KeyGeneration(p, q)
        self._private_key = keys.generate_private_key()
        self._public_key = keys.generate_public_key()

        self._alphabet = Alphabet()

    @staticmethod
    def __divide_by_two(p: int) -> tuple:
        s = 0
        t = p - 1
        while t % 2 == 0:
            s += 1
            t = (p - 1) // (2 ** s)
        return s, t

    def __jacobi_symbol(self, n: int, p: int) -> int:
        if p <= 0:
            raise ValueError("'n' must be a positive integer.")
        if p % 2 == 0:
            raise ValueError("'n' must be odd.")
        n %= p
        result = 1
        while n != 0:
            while n % 2 == 0:
                n /= 2
                n_mod_8 = p % 8
                if n_mod_8 in (3, 5):
                    result = -result
            n, p = p, n
            if n % 4 == 3 and p % 4 == 3:
                result = -result
            n %= p
        if p == 1:
            return result
        else:
            return 0

    def __generate_quadratic_non_residue(self, p: int) -> int:
        for d in range(2, p):
            if self.__jacobi_symbol(d, p) == -1:
                return d

    def __modular_square_root(self, a: int, p: int) -> int:
        if p % 2 == 1:
            if p % 8 == 1:
                s, t = self.__divide_by_two(p)
                d = self.__generate_quadratic_non_residue(p)
                A = a ** t % p
                D = d ** t % p
                D_to_the_power_of_minus_1 = pow(D, -1, p)
                for k in range(1, 2 ** (s - 1)):
                    if (D_to_the_power_of_minus_1 ** (2 * k)) % p == A:
                        return (a ** ((t + 1) // 2) * (D ** k)) % p
            elif p % 4 == 3:
                return a ** ((p + 1) // 4) % p
            elif p % 8 == 5:
                if a ** ((p - 1) // 4) % p == 1:
                    return a ** ((p + 3) // 8) % p
                else:
                    return (2 * a * ((4 * a) ** ((p - 5) // 8))) % p

    def chinese_remainder_theorem(self, a: int, b: int) -> int:
        return (a * self._private_key[1] * pow(self._private_key[1], -1, self._private_key[0]) + b * self._private_key[0] * pow(self._private_key[0], -1, self._private_key[1])) % self._public_key

    def __decrypt(self, c: int) -> tuple:
        r1 = self.__modular_square_root(c, self._private_key[0])
        r2 = self._private_key[0] - r1
        r3 = self.__modular_square_root(c, self._private_key[1])
        r4 = self._private_key[1] - r3

        x1 = self.chinese_remainder_theorem(r1, r3)
        x2 = self.chinese_remainder_theorem(r1, r4)
        x3 = self.chinese_remainder_theorem(r2, r3)
        x4 = self.chinese_remainder_theorem(r2, r4)

        return x1, x2, x3, x4

    @staticmethod
    def __get_m_with_the_replicated_last_k_bits(m0: int, k: int) -> int:
        m0_as_bit_field = [int(digit) for digit in bin(m0)[2:]]

        while len(m0_as_bit_field) < 8:
            m0_as_bit_field.insert(0, 0)

        m_as_bit_field = copy.deepcopy(m0_as_bit_field)

        if len(m_as_bit_field) < k:
            raise Exception(f"There aren't enough bits in the message to replicate the last {k} bits.")

        m_as_bit_field.extend(m0_as_bit_field[-k:])

        m = 0
        for bit in m_as_bit_field:
            m = (m << 1) | bit

        return m

    def __encrypt(self, m: int) -> int:
        return self.__get_m_with_the_replicated_last_k_bits(m, self._bit_count_used_for_validation) ** 2 % self._public_key

    def encrypt(self, plaintext: str, k: int, l: int) -> str:
        if not (27 ** k < self._public_key < 27 ** l):
            raise Exception(f"k = {k} and l = {l} are not valid for n = {self._public_key}")

        print(f"plaintext: {plaintext}")

        plaintext_blocks = self._alphabet.split_text_to_blocks(plaintext, k)
        print(f"plaintext in blocks of {k} letters: {plaintext_blocks}")

        plaintext_numerical_equivalents = self._alphabet.convert_blocks_to_numerical_equivalents(plaintext_blocks)
        print("plaintext numerical equivalents: ", plaintext_numerical_equivalents)

        encrypted_numerical_equivalents = [self.__encrypt(m) for m in plaintext_numerical_equivalents]
        print("encrypted numerical equivalents: ", encrypted_numerical_equivalents)

        ciphertext_blocks = self._alphabet.convert_numerical_equivalents_to_blocks(encrypted_numerical_equivalents, l)
        print(f"ciphertext in blocks of {l} letters: {ciphertext_blocks}")

        ciphertext = "".join(ciphertext_blocks)

        return ciphertext

    def __are_the_last_k_bits_replicated(self, m: int) -> bool:
        m_as_bit_field = [int(digit) for digit in bin(m)[2:]]

        while len(m_as_bit_field) < 8:
            m_as_bit_field.insert(0, 0)

        if len(m_as_bit_field) < 2 * self._bit_count_used_for_validation:
            raise Exception(f"There aren't enough bits in the message to check if the last {self._bit_count_used_for_validation} bits are replicated.")

        return m_as_bit_field[-self._bit_count_used_for_validation:] == m_as_bit_field[-2 * self._bit_count_used_for_validation:-self._bit_count_used_for_validation]

    def __get_m_without_the_replicated_last_k_bits(self, m: int) -> int:
        m_as_bit_field = [int(digit) for digit in bin(m)[2:]]

        while len(m_as_bit_field) < 8:
            m_as_bit_field.insert(0, 0)

        m1_as_bit_field = copy.deepcopy(m_as_bit_field)

        if len(m1_as_bit_field) < self._bit_count_used_for_validation:
            raise Exception(f"There aren't enough bits in the message to remove the replicated last {self._bit_count_used_for_validation} bits.")

        del m1_as_bit_field[-self._bit_count_used_for_validation:]

        m1 = 0
        for bit in m1_as_bit_field:
            m1 = (m1 << 1) | bit

        return m1

    def __find_acceptable_solution(self, solutions: list, k: int) -> int:
        acceptable_solutions = []
        for solution in solutions:
            if self.__are_the_last_k_bits_replicated(solution):
                possible_solution = self.__get_m_without_the_replicated_last_k_bits(solution)
                if possible_solution < 27 ** k:
                    acceptable_solutions.append(possible_solution)

        if len(acceptable_solutions) < 1:
            raise Exception("No acceptable solutions have been found.")
        elif len(acceptable_solutions) > 1:
            raise Exception("Too many acceptable solutions have been found.")

        return acceptable_solutions[0]

    def decrypt(self, ciphertext, k: int, l: int) -> str:
        if not (27 ** k < self._public_key < 27 ** l):
            raise Exception(f"k = {k} and l = {l} are not valid for n = {self._public_key}")

        print(f"ciphertext: {ciphertext}")

        ciphertext_blocks = self._alphabet.split_text_to_blocks(ciphertext, l)
        print(f"ciphertext in blocks of {l} letters: {ciphertext_blocks}")

        ciphertext_numerical_equivalents = self._alphabet.convert_blocks_to_numerical_equivalents(ciphertext_blocks)
        print("ciphertext numerical equivalents: ", ciphertext_numerical_equivalents)

        decrypted_possible_numerical_equivalents = [self.__decrypt(ciphertext_numerical_equivalent) for ciphertext_numerical_equivalent in ciphertext_numerical_equivalents]
        print("decrypted possible numerical equivalents: ", decrypted_possible_numerical_equivalents)

        decrypted_numerical_equivalents = [self.__find_acceptable_solution(list(possible_numerical_equivalents), k) for possible_numerical_equivalents in decrypted_possible_numerical_equivalents]
        print("decrypted numerical equivalents: ", decrypted_numerical_equivalents)

        plaintext_blocks = self._alphabet.convert_numerical_equivalents_to_blocks(decrypted_numerical_equivalents, k)
        print(f"plaintext in blocks of {k} letters: {plaintext_blocks}")

        plaintext = "".join(plaintext_blocks)

        return plaintext
