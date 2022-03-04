from key_pair_gen import KeyGen

from base64 import b64decode
import sys

PRIVATE_PEM = 'private.pem'
PUBLIC_PEM = 'public.pem'
EXTENSION = '.pem'

INPUT_ERROR = '''
rsagen.py <private_pem> <public_pem>'

    - private_pem -> String
    - public_pem -> String

2 args creates the two files w/ the given names;
No args creates the two files w/ default names;
Otherwise an error is thrown.
'''

def input_error():
    print(INPUT_ERROR)
    sys.exit(2)

def run(private_pem, public_pem):
    generator = KeyGen(b64decode(sys.stdin.read().encode('ascii')))
    prv_k, pub_k = generator.generate()
    private_pem = open(private_pem, 'wb')
    private_pem.write(prv_k)
    private_pem.close()
    public_pem = open(public_pem, 'wb')
    public_pem.write(pub_k)
    public_pem.close()

def main(argv):
    # Set up the application:
    private_pem, public_pem = PRIVATE_PEM, PUBLIC_PEM
    if len(argv) not in (0, 2):
        input_error()
    if len(argv) == 2:
        private_pem, public_pem = argv[0], argv[1]
        if private_pem[-4:] != EXTENSION:
            private_pem += EXTENSION
        if public_pem[-4:] != EXTENSION:
            public_pem += EXTENSION
    run(private_pem, public_pem)

if __name__ == '__main__':
    main(sys.argv[1:])
