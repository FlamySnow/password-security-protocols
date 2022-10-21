import argparse
from verifier import verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', help="Output information of cracking process")
    parser.add_argument("file", help="Path to file")
    args = parser.parse_args()
    v = args.verbose
    pathfile = args.file
    if not verify(pathfile):
        raise Exception("File is not valid!")
    if v:
        print("Valid file!")
    with open(pathfile, 'rb') as file:
        file.read(3)  # Pass ENC
        hash_byte = file.read(1)
        cipher_byte = file.read(1)

    if v:
        print(f'Hash function: {hash_func}\nCipher algorythm: {cipher}\n')


