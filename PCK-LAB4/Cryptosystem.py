import copy
import random
from typing import Tuple, Union, Any, List

from Alphabet import Alphabet
from KeyGeneration import KeyGeneration


class Cryptosystem:
    def __find_fitting_redundancy(self, bit_count: int) -> int:
        redundancy: int = self.__smallest_power_of_2_greater_or_equal_to(bit_count) - bit_count

        # Whatever's down here is more of a hack than a solution. Not sure if it entirely works in the long run.
        #
        # upper_bound_for_redundancy: int = self.__highest_power_of_2_lesser_than(len(self.__get_the_bit_field_of(self._public_key)))
        # if redundancy < 1 or redundancy > upper_bound_for_redundancy:
        #     redundancy = upper_bound_for_redundancy - bit_count

        return redundancy

    @staticmethod
    def __smallest_power_of_2_greater_or_equal_to(number: int) -> int:
        p = 1
        if number and not (number & (number - 1)):
            return number

        while p < number:
            p <<= 1

        return p

    @staticmethod
    def __highest_power_of_2_lesser_than(number: int) -> int:
        n = number
        if n & (n - 1) == 0:
            n -= 1
        while n & (n - 1) != 0:
            n = n & (n - 1)
        return n

    def __init__(self, p: int = 0, q: int = 0):
        print("Rabin Cryptosystem initializing...")
        #The keys are generated
        print("Generating keys...")
        if p == 0 and q == 0:
            keys = KeyGeneration()
        else:
            keys = KeyGeneration(p, q)
        self._private_key = keys.generate_private_key()
        print(f"Private keys generated: {self._private_key}.")
        self._public_key = keys.generate_public_key()
        print(f"Public key generated: {self._public_key}.")

        #Here the alphabet is initialized
        self._alphabet = Alphabet()
        print("Alphabet initialized.")
        print("Rabin Cryptosystem initialized.")
        print()

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
            raise Exception("'n' must be a positive integer.")
        if p % 2 == 0:
            raise Exception("'n' must be odd.")
        if p >= 3:
            raise Exception("'n' must be equal or bigger then 3")
        n %= p
        result = 1
        while n != 0:
            while n % 2 == 0:
                n /= 2
                n_mod_8 = p % 8
                if n_mod_8 in (3, 5):
                    result = -result
            #(Law of Quadratic Reciprocity)
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
        return (a * self._private_key[1] * pow(self._private_key[1], -1, self._private_key[0]) + b * self._private_key[
            0] * pow(self._private_key[0], -1, self._private_key[1])) % self._public_key

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
    def __get_the_bit_field_of(number: int) -> list[int]:
        number_as_bit_field = [int(digit) for digit in bin(number)[2:]]
        return number_as_bit_field

    def __get_m_with_the_replicated_last_k_bits(self, m0: int, k: int) -> int:
        if k == 0:
            return m0

        m0_as_bit_field = self.__get_the_bit_field_of(m0)

        m_as_bit_field = copy.deepcopy(m0_as_bit_field)

        if len(m_as_bit_field) < k:
            raise Exception(f"There aren't enough bits in the message to replicate the last {k} bits.")

        m_as_bit_field.extend(m0_as_bit_field[-k:])

        m = 0
        for bit in m_as_bit_field:
            m = (m << 1) | bit

        return m

    def __encrypt(self, m: int) -> int:
        return m ** 2 % self._public_key

    def encrypt(self, plaintext: str, k: int = 0, l: int = 0) -> tuple[str, list[int]]:
        if not (27 ** k < self._public_key < 27 ** l):
            raise Exception(f"k = {k} and l = {l} are not valid for n = {self._public_key}")

        print(f"Plaintext: {plaintext}")

        plaintext_blocks = self._alphabet.split_text_to_blocks(plaintext, k)
        print(f"Plaintext in Blocks of {k} Letters: {plaintext_blocks}")

        plaintext_numerical_equivalents = self._alphabet.convert_blocks_to_numerical_equivalents(plaintext_blocks)
        print("Plaintext Numerical Equivalents: ", plaintext_numerical_equivalents)

        plaintext_redundancies = [self.__find_fitting_redundancy(len(self.__get_the_bit_field_of(numerical_equivalent))) for numerical_equivalent in plaintext_numerical_equivalents]
        print("Plaintext Redundancies: ", plaintext_redundancies)

        plaintext_numerical_equivalents_with_redundancy = []
        for index in range(len(plaintext_numerical_equivalents)):
            plaintext_numerical_equivalents_with_redundancy.append(
                self.__get_m_with_the_replicated_last_k_bits(plaintext_numerical_equivalents[index], plaintext_redundancies[index]))
        print("Plaintext Numerical Equivalents with Redundancy: ", plaintext_numerical_equivalents_with_redundancy)

        encrypted_numerical_equivalents = [self.__encrypt(m) for m in plaintext_numerical_equivalents_with_redundancy]
        print("Encrypted Numerical Equivalents: ", encrypted_numerical_equivalents)

        ciphertext_blocks = self._alphabet.convert_numerical_equivalents_to_blocks(encrypted_numerical_equivalents, l)
        print(f"Ciphertext in Blocks of {l} Letters: {ciphertext_blocks}")

        ciphertext = "".join(ciphertext_blocks)
        print()

        return ciphertext, plaintext_redundancies

    def __are_the_last_k_bits_replicated(self, m: int, k: int) -> bool:
        if k == 0:
            return True

        m_as_bit_field = [int(digit) for digit in bin(m)[2:]]

        if len(m_as_bit_field) < 2 * k:
            raise Exception(f"There aren't enough bits in the message to check if the last {k} bits are replicated for message {m}.")

        return m_as_bit_field[-k:] == m_as_bit_field[-2 * k:-k]

    def __get_m_without_the_replicated_last_k_bits(self, m: int, k: int) -> int:
        if k == 0:
            return m

        m_as_bit_field = [int(digit) for digit in bin(m)[2:]]

        m_as_bit_field_initial_length = len(m_as_bit_field)
        while len(m_as_bit_field) < self.__smallest_power_of_2_greater_or_equal_to(m_as_bit_field_initial_length):
            m_as_bit_field.insert(0, 0)

        m1_as_bit_field = copy.deepcopy(m_as_bit_field)

        if len(m1_as_bit_field) < k:
            raise Exception(f"There aren't enough bits in the message to remove the replicated last {k} bits.")

        del m1_as_bit_field[-k:]

        m1 = 0
        for bit in m1_as_bit_field:
            m1 = (m1 << 1) | bit

        return m1

    def __find_acceptable_solution(self, solutions: list, redundancy: int, k: int) -> int:
        acceptable_solutions = []
        for solution in solutions:
            if self.__are_the_last_k_bits_replicated(solution, redundancy):
                possible_solution = self.__get_m_without_the_replicated_last_k_bits(solution, redundancy)
                if possible_solution < 27 ** k:
                    acceptable_solutions.append(possible_solution)

        if len(acceptable_solutions) < 1:
            raise Exception(f"No acceptable solutions have been found for solutions {solutions}.")
        elif len(acceptable_solutions) > 1:
            raise Exception(f"Too many acceptable solutions {acceptable_solutions} have been found for solutions {solutions}.")

        return acceptable_solutions[0]

    def decrypt(self, ciphertext: str, redundancies: list[int], k: int, l: int) -> str:
        if not (27 ** k < self._public_key < 27 ** l):
            raise Exception(f"k = {k} and l = {l} are not valid for n = {self._public_key}")

        print(f"Ciphertext: {ciphertext}")

        ciphertext_blocks = self._alphabet.split_text_to_blocks(ciphertext, l)
        print(f"Ciphertext in Blocks of {l} Letters: {ciphertext_blocks}")

        ciphertext_numerical_equivalents = self._alphabet.convert_blocks_to_numerical_equivalents(ciphertext_blocks)
        print("Ciphertext Numerical Equivalents: ", ciphertext_numerical_equivalents)

        decrypted_possible_numerical_equivalents = [self.__decrypt(ciphertext_numerical_equivalent) for
                                                    ciphertext_numerical_equivalent in ciphertext_numerical_equivalents]
        print("Decrypted Possible Numerical Equivalents: ", decrypted_possible_numerical_equivalents)

        decrypted_numerical_equivalents = []
        for index in range(len(decrypted_possible_numerical_equivalents)):
            decrypted_numerical_equivalents.append(self.__find_acceptable_solution(list(decrypted_possible_numerical_equivalents[index]), redundancies[index], k))
        print("Decrypted Numerical Equivalents: ", decrypted_numerical_equivalents)

        plaintext_blocks = self._alphabet.convert_numerical_equivalents_to_blocks(decrypted_numerical_equivalents, k)
        print(f"Plaintext in Blocks of {k} Letters: {plaintext_blocks}")

        plaintext = "".join(plaintext_blocks)
        print()

        return plaintext
