import argparse
from gen import NONCE_SIZE, AES_IV_SIZE, TDES_IV_SIZE
from Crypto.Cipher import AES, DES3


def verify(pathfile: str) -> bool:
    ext = pathfile.split('.')[-1]
    if ext != 'enc':
        return False
    with open(pathfile, 'rb') as file:
        sign = file.read(3).decode('ascii')
        if sign != 'ENC':
            print(sign)
            return False
        hash_byte = file.read(1)
        if hash_byte != b'\x00' and hash_byte != b'\x01':
            return False
        cipher_byte = file.read(1)
        if cipher_byte != b'\x00' and cipher_byte != b'\x01' and cipher_byte != b'\x02' and cipher_byte != b'\x03':
            return False
        file.read(NONCE_SIZE)
        if cipher_byte == b'\x00':
            file.read(TDES_IV_SIZE)
            cipher_text = file.read()
            if len(cipher_text) % DES3.block_size != 0:
                return False
        else:
            file.read(AES_IV_SIZE)
            cipher_text = file.read()
            if len(cipher_text) % AES.block_size != 0:
                return False
    return True


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description="Verification for files encrypted by study cipher")
        parser.add_argument("file", help="File with extension '.enc'")
        args = parser.parse_args()
        path = args.file
        print(verify(path))
    except Exception as msg:
        print(msg)
        print(False)
