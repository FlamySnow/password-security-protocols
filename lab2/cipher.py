import argparse
import os.path
from encryption import encrypt


def main():
    parser = argparse.ArgumentParser(prog='AES Cipher', description='AES encryption and decryption in ECB or CBC '
                                                                    'modes.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1', help="Prints version of program.")
    parser.add_argument('-m', '--mode', choices=['ecb', 'cbc'], required=True, help="Sets block cipher mode.")
    parser.add_argument('-e', '--enc', action='store_true', help="Flag for encryption.")
    parser.add_argument('-d', '--dec', action='store_true', help="Flag for decryption.")
    parser.add_argument('-k', '--key', required=True, help="32-bit key for encryption/decryption.")
    parser.add_argument('-i', '--iv', help="32-bit initialization vector for CBC mode.")
    parser.add_argument('-g', '--debug', action='store_true', help="Flag for logging intermediate states of "
                                                                   "encryption/decryption.")
    parser.add_argument('input_file', help="File with input data in hex format. Must exist.")
    parser.add_argument('output_file', help="Name of output file.")
    try:
        args = parser.parse_args()
        if not os.path.isfile(args.input_file):
            raise Exception("Input file doesn't exist!")
        enc = args.enc
        dec = args.dec
        key = bytearray.fromhex(args.key)
        mode = args.mode
        iv = bytearray.fromhex(args.iv)
        if mode == 'cbc' and iv is None:
            raise Exception("Initialization vector is needed in CBC mode. Try option -i or --iv.")
        dbg = args.debug
        data = bytearray.fromhex(open(args.input_file, 'r').read())
        if enc:
            cipher_text = encrypt(data, key, mode, dbg, iv).hex()
            output = open(args.output_file, 'w')
            output.write(cipher_text)
            output.close()
            print("Cipher text: ", cipher_text)
    except Exception as msg:
        print(msg)


if __name__ == '__main__':
    main()
