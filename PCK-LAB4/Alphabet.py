import string


class Alphabet:
    def __init__(self, blank_character: string, alphabet: string):
        self._blank_character: string = blank_character
        self._alphabet: list = [blank_character] + [*alphabet]
