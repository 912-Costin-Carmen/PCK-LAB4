# This is a sample Python script.
from Cryptosystem import Cryptosystem

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    rabin = Cryptosystem(179, 499)
    ciphertext, redundancies = rabin.encrypt("GAME", 3, 4)
    print()
    plaintext = rabin.decrypt(ciphertext, redundancies, 3, 4)


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
