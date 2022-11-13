import argparse
from gen import generate, SHA1, MD5

num = '0123456789'
small = 'abcdefghijklmnopqrstuvwxyz'
big = small.upper()
a = ''.join([num, small, big])
SHA1_SIZE = 20
MD5_SIZE = 16


def main():
    parser = argparse.ArgumentParser("This script picks up a password for protocol IKEv1 Aggressive Mode")
    parser.add_argument("-m", required=True, help="Mask for password")
    parser.add_argument("input_file", help="File with protocol data")
    args = parser.parse_args()
    mask = list(args.m)
    filename = args.input_file
    str_data = open(filename, 'r').read().split('*')
    # Ni = data[0]
    # Nr = data[1]
    # g_x = data[2]
    # g_y = data[3]
    # Ci = data[4]
    # Cr = data[5]
    # SAi = data[6]
    # IDr = data[7]
    # HASH = data[8]
    data = [bytes.fromhex(x) for x in str_data]
    if len(data[8]) == SHA1_SIZE:
        hash_function = SHA1
    elif len(data[8]) == MD5_SIZE:
        hash_function = MD5
    else:
        raise Exception("Invalid size of cache!")
    temp = []
    for m in mask:
        match m:
            case 'a':
                temp.append([list(a), 0])
            case 's':
                temp.append([list(small), 0])
            case 'l':
                temp.append([list(big), 0])
            case 'd':
                temp.append([list(num), 0])
            case _:
                raise Exception("Invalid symbols for mask!")
    while temp[len(temp) - 1][1] < len(temp[len(temp) - 1][0]):
        candidate = [x[0][x[1]] for x in temp]
        password = ''.join(candidate).encode()
        if data[8] == generate(password, hash_function, data):
            print(f'Found: {password.decode()}')
            return
        for m in temp:
            if m[1] < len(m[0]) - 1:
                m[1] += 1
                break
            else:
                m[1] = 0
    print("Not found")


if __name__ == '__main__':
    main()
