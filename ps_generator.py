from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import copy

SEED_LEN = 64

# Generates a single byte at a time:
class ByteGen(object):
    
    def __init__(self, key, iv):
        # Generator's state:
        self.key = key
        self.iv = iv
        self.block = b''
        # Cipher mode ECB:
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        self.cipher = cipher.encryptor()

    def __get_block(self):
        return self.cipher.update(self.iv)

    def generate(self):
        # Cipher mode ends up being OFB:
        if self.block == b'':
            self.block = self.__get_block()
            self.iv = self.block
        # Yield one byte at a time:
        b = self.block[0]
        self.block = self.block[1:]
        return bytes([b])

# Executes one iteration of the generator:
class StreamGen(object):

    def __init__(self, key, iv, pattern):
        self.generator = ByteGen(key, iv)
        self.pattern = pattern

    # Use the byte generator to generate a 32-bit seed:
    def __seed(self):
        seed = b''
        for _ in range(SEED_LEN):
            seed += self.generator.generate()
        return seed

    # Performs one of the iterations defined by the input:
    def __generate(self):
        pattern = self.pattern
        stream = b''
        # The iteration lasts as long as there are bytes 
        # in the pattern left to be found:
        while pattern:
            b = self.generator.generate()
            pattern = self.__find_and_remove_byte(b, pattern)
            stream += b
        return stream

    # Full iteration:
    # (stream followed by key generation)
    def iteration(self):
        return self.__generate(), self.__seed()

    # Find if a bytearray contains a byte
    # and if so, remove it:
    @staticmethod
    def __find_and_remove_byte(t, l):
        t = list(t)[0]
        l = list(l)
        if t == l[0]:
            del l[0]
        return bytes(l)

# Executes ni iterations of the generator:
class MainGen(object):

    def __init__(self, seed, pattern, ni):
        # Process bootstrap seed:
        key, iv = self.__key_iv(seed)
        self.__pattern = pattern
        # Init stream generator:
        self.generator = StreamGen(key, iv, self.pattern)
        self.ni = ni

    # Use a new reference for pattern, to avoid modifying it:
    @property
    def pattern(self):
        return copy.deepcopy(self.__pattern)

    @staticmethod
    def __key_iv(seed):
        # Build iv from odd indices:
        key, iv = b'', b''
        for i in range(1, len(seed), 2):
            iv += bytes([seed[i]])
        # Build key from even indices:
        for i in range(0, len(seed), 2):
            key += bytes([seed[i]])
        return key, iv

    def generate(self):
        stream = b''
        for _ in range(self.ni):
            segment, seed = self.generator.iteration()
            stream += segment
            key, iv = self.__key_iv(seed)
            # Restart stream generator (new state):
            # (new key, new iv, same pattern)
            self.generator = StreamGen(key, iv, self.pattern)
        return stream

# Manages the generator's execution:
class Generator(object):

    def __init__(self, password, pattern, ni):
        seed = self.__bootstrap_seed(password, pattern, ni)
        pattern = self.__transform_pattern(pattern)
        self.generator = MainGen(seed, pattern, ni)

    @staticmethod
    def __bootstrap_seed(password, pattern, iterations):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=SEED_LEN,
            salt=pattern.encode('ascii') if type(pattern) is str else pattern,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('ascii') if type(password) is str else password)

    # Transform the pattern into a same length byte array w/ any value:
    @staticmethod
    def __transform_pattern(pattern):
        hash = hashes.Hash(hashes.SHAKE256(len(pattern)), backend=default_backend())
        hash.update(pattern.encode('ascii') if type(pattern) is str else pattern)
        return hash.finalize()

    # Stream generation:
    # (previous execution affects the current one)
    def generate(self):
        return self.generator.generate()
