# This is a sample Python script.
from Cryptosystem import Cryptosystem

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    rabin = Cryptosystem(2, 277, 331)
    ciphertext = rabin.encrypt("GAMING", 2, 4)
    plaintext = rabin.decrypt(ciphertext, 2, 4)


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
