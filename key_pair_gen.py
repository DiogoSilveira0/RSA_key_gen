from Crypto.PublicKey import RSA
from gmpy2 import mpz
import random

PRIME_SIZE_BYTES = 128
EXPONENT = 65537
K_ROUNDS = 40

'''
Extracts p and q from the bytestream.
'''
class PrimeGen(object):

    def __init__(self, stream):
        self.stream = stream

    @property
    def __step(self):
        return len(self.stream) // PRIME_SIZE_BYTES

    @property
    def __shift(self):
        return len(self.stream) % PRIME_SIZE_BYTES

    @property
    def __p(self):
        return mpz(int.from_bytes(bytes([self.stream[i] for i in range(0, len(self.stream), self.__step)][:PRIME_SIZE_BYTES]), 'big'))

    @property
    def __q(self):
        return mpz(int.from_bytes(bytes([self.stream[i] for i in range(self.__shift, len(self.stream), self.__step)][:PRIME_SIZE_BYTES]), 'big'))

    # Miller-Rabin Test:
    # (optimal number of rounds is 40)
    # (Based on code from https://gist.github.com/Ayrx/5884790 
    # and https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller%E2%80%93Rabin_test)
    @staticmethod
    def __is_prime(number):
        # 2 is prime:
        if number == 2:
            return True
        # Even numbers (except 2) are not prime:
        if number % 2 == 0:
            return False
        # Write number as 2^r * d + 1:
        r, d = 0, number - 1
        # d must be odd:
        while d % 2 == 0:
            r += 1
            # Decompose d:
            d //= 2
        for _ in range(K_ROUNDS):
            # Pick a random integer within this range:
            a = random.randrange(2, number - 1)
            # pow(base, exp, mode):
            x = pow(a, d, number)
            if x == 1 or x == number - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, number)
                if x == number - 1:
                    break
            else:
                return False
        return True

    def __gen_prime_from(self, number):
        # Make sure number is odd:
        if number % 2 == 0:
            number = number + 1
        # Then iterate with a step of 2 numbers:
        while not self.__is_prime(number):
            number += 2
        return number

    def generate(self):
        return self.__gen_prime_from(self.__p), self.__gen_prime_from(self.__q)

'''
After extracting p and q, computes the key pair.
'''
class KeyGen(PrimeGen):

    def __init__(self, stream):
        super().__init__(stream)
        self.p, self.q, self.n, self.e, self.d = None, None, None, EXPONENT, None

    def generate(self):
        self.p, self.q = super().generate()
        self.n = self.p * self.q
        self.d = self.__private()
        key = RSA.construct((int(self.n), int(self.e), int(self.d)), True)
        return key.export_key(pkcs=8), key.publickey().export_key(pkcs=8)

    # Based on code from https://coderoasis.com/implementing-rsa-from-scratch-in-python/:
    @staticmethod
    def __euclidean(a, b):
        # Keep a > b:
        swapped = False
        if a < b:
            a, b = b, a
            swapped = True
        # Current values of a and b in the form of coefficients:
        current_a, current_b = (1, 0), (0, 1)
        while b != 0:
            # How many times we can subtract b from a:
            k = a // b
            # Subtract b from a k times:
            a, b, current_a, current_b = b, a - b * k, current_b, (current_a[0] - k * current_b[0], current_a[1] - k * current_b[1])
        # Get back the order and return:
        return current_a if not swapped else current_a[1], current_a[0]

    # Based on code from https://coderoasis.com/implementing-rsa-from-scratch-in-python/:
    def __private(self):
        totient = (self.p - 1) * (self.q - 1)
        d = self.__euclidean(self.e, totient)[0]
        if d < 0:
            d += totient
        return d
