import argparse
from gen import generate
import itertools

num = '0123456789'
small = 'abcdefghijklmnopqrstuvwxyz'
big = small.upper()
a = ''.join([num, small, big])


def main():
    parser = argparse.ArgumentParser("This script picks up a password for protocol IKEv1 Aggressive Mode")
    parser.add_argument("-m", required=True, help="Mask for password")
    parser.add_argument("input_file", help="File with protocol data")
    args = parser.parse_args()
    mask = list(args.m)
    filename = args.input_file
    data = open(filename, 'r').read().split('*')
    Ni = data[0]
    Nr = data[1]
    g_x = data[2]
    g_y = data[3]
    Ci = data[4]
    Cr = data[5]
    SAi = data[6]
    IDr = data[7]
    HASH = data[8]
    candidate = []
    for i in range(0, len(mask)):
        match mask[i]:
            case 'a':
                if i == 0:
                    candidate = [''.join(x) for x in itertools.product(a, repeat=1)]
                else:
                    new_candidates = []
                    for c in candidate:
                        for y in [''.join([c, ''.join(x)]) for x in itertools.product(a, repeat=1)]:
                            new_candidates.append(y)
                    candidate = new_candidates
            case 's':
                if i == 0:
                    candidate = [''.join(x) for x in itertools.product(small, repeat=1)]
                else:
                    new_candidates = []
                    for c in candidate:
                        for y in [''.join([c, ''.join(x)]) for x in itertools.product(small, repeat=1)]:
                            new_candidates.append(y)
                    candidate = new_candidates
            case 'l':
                if i == 0:
                    candidate = [''.join(x) for x in itertools.product(big, repeat=1)]
                else:
                    new_candidates = []
                    for c in candidate:
                        for y in [''.join([c, ''.join(x)]) for x in itertools.product(big, repeat=1)]:
                            new_candidates.append(y)
                    candidate = new_candidates
            case 'd':
                if i == 0:
                    candidate = [''.join(x) for x in itertools.product(num, repeat=1)]
                else:
                    new_candidates = []
                    for c in candidate:
                        for y in [''.join([c, ''.join(x)]) for x in itertools.product(num, repeat=1)]:
                            new_candidates.append(y)
                    candidate = new_candidates
    m = small, big, big
    for x in itertools.product(small, big, big, a, a, a):
        print(''.join(x))


if __name__ == '__main__':
    main()
