from typing import List, Any


class Alphabet:
    def __init__(self):
        self._blank_character: str = "_"
        self._alphabet: list = [self._blank_character] + [chr(asciiCode) for asciiCode in range(ord('A'), ord('Z') + 1)]

    def __code(self, letter: str) -> int:
        return self._alphabet.index(letter)

    def __is_valid_character(self, character: str) -> bool:
        return character in self._alphabet

    def split_text_to_blocks(self, message: str, step: int) -> list[str]:
        for character in list(message):
            if not self.__is_valid_character(character):
                raise Exception("The message contains invalid characters.")

        blocks: list[str] = [message[index:index + step] for index in range(0, len(message), step)]
        blocks[-1] += self._blank_character * (step - len(blocks[-1]))
        return blocks

    def convert_blocks_to_numerical_equivalents(self, blocks: list[str]) -> list[int]:
        numerical_equivalents: list[int] = []
        for block in blocks:
            numerical_equivalents.append(self.__convert_block_to_numerical_equivalent(block))
        return numerical_equivalents

    def __convert_block_to_numerical_equivalent(self, block: str) -> int:
        return sum(self.__code(character) * pow(len(self._alphabet), len(block) - index - 1) for index, character in enumerate(block))

    def convert_numerical_equivalents_to_blocks(self, numerical_equivalents: list[int], step: int) -> list[str]:
        blocks: list[str] = []
        for numerical_equivalent in numerical_equivalents:
            blocks.append(self.__convert_numerical_equivalent_to_block(numerical_equivalent, step))
        return blocks

    def __convert_numerical_equivalent_to_block(self, numerical_equivalent: int, step: int) -> str:
        alphabet_indexes: list[int] = []
        while numerical_equivalent > 0:
            alphabet_indexes.insert(0, numerical_equivalent % len(self._alphabet))
            numerical_equivalent //= len(self._alphabet)

        padding = self._blank_character * (step - len(alphabet_indexes))
        return padding + "".join(self._alphabet[index] for index in alphabet_indexes)
