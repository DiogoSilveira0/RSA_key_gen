from ps_generator import Generator

from base64 import b64encode
import sys
import os

import matplotlib.pyplot as plt
import time

INPUT_ERROR = '''
randgen.py <password> <confusion_string> <iterations>'

    - password -> String
    - confusion_string -> String
    - iterations -> Integer

3 args outputs a bytestream to stdout;
No args runs test mode;
Otherwise an error is thrown.
'''

def input_error():
    print(INPUT_ERROR)
    sys.exit(2)

def output(params):
    generator = Generator(params[0], params[1], params[2])
    sys.stdout.write(b64encode(generator.generate()).decode('ascii'))

def chart(results):
    nis = list(results.keys())
    for i in nis:
        strings = list(results[i].keys())
        times = []
        for s in strings:
            times.append(results[i][s])
        x = [len(s) for s in strings]
        y = times
        plt.scatter(x, y, label=str(i) + ' iterations')
        plt.plot(x, y, label=str(i) + ' iterations')
    plt.xlabel('x - string length (bytes)')
    plt.ylabel('y - elapsed time(seconds)')
    plt.legend()
    plt.show()

def test():
    password = os.urandom(16)
    nis = [1000, 5000, 10000, 20000, 50000]
    strings = [os.urandom(i) for i in range(1, 17, 2)]
    results = dict()
    it = 1
    for i in nis:
        temp = {}
        for s in strings:
            print(it, end='\r')
            generator = Generator(password, s, i)
            start = time.time()
            generator.generate()
            end = time.time()
            temp[s] = end - start
            it += 1
        results[i] = temp
    chart(results)

def main(argv):
    # Set up the application:
    if len(argv) not in (0, 3):
        input_error()
    if len(argv) == 3:
        try:
            argv = (argv[0].encode('ascii'), argv[1].encode('ascii'), int(argv[2]))
            output(argv)
        except:
            input_error()
    else:
        test()

if __name__ == '__main__':
    main(sys.argv[1:])
