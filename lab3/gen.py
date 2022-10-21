import argparse
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA1
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad
import os

MAX_SIZE = 4096
KEY_SIZE = 4
NONCE_SIZE = 64
TDES_KEY_SIZE = 24
AES128_KEY_SIZE = 16
AES192_KEY_SIZE = 24
AES256_KEY_SIZE = 32
TDES_IV_SIZE = 8
AES_IV_SIZE = 16
PADDING = b'\x00\x00\x00\x00\x00\x00\x00\x00'


def adjust_key_size(key: bytes, hmac: HMAC, key_size: int) -> bytes:
    h_key = hmac.digest()
    if len(h_key) < key_size:
        while len(h_key) < key_size:
            hmac.update(key)
            new_h_key = hmac.digest()
            h_key = b''.join([h_key, new_h_key])
    if len(h_key) > key_size:
        h_key = h_key[:key_size]
    return h_key


def generate_key(key: bytes, nonce: bytes, hash_fun: str, cipher: str) -> bytes:
    if hash_fun == 'sha1':
        hmac = HMAC.new(key, nonce, SHA1)
    else:
        hmac = HMAC.new(key, nonce)  # MD5 is used by default
    match cipher:
        case '3des':
            return adjust_key_size(key, hmac, TDES_KEY_SIZE)
        case 'aes128':
            return adjust_key_size(key, hmac, AES128_KEY_SIZE)
        case 'aes192':
            return adjust_key_size(key, hmac, AES192_KEY_SIZE)
        case 'aes256':
            return adjust_key_size(key, hmac, AES256_KEY_SIZE)
        case _:
            raise Exception('Invalid encryption cipher!')


def encrypt(data: bytes, key: bytes, hash_fun: str, cipher: str) -> (bytes, bytes, bytes):
    if len(data) > MAX_SIZE:
        raise Exception(f"Length of data can't be above 4096 bytes! Current length of data is {len(data)}")
    nonce = get_random_bytes(NONCE_SIZE)
    plain_text = b''.join([PADDING, data])
    h_key = generate_key(key, nonce, hash_fun, cipher)
    if cipher == '3des':
        in_key = DES3.adjust_key_parity(h_key)
        iv = get_random_bytes(TDES_IV_SIZE)
        tdes = DES3.new(in_key, DES3.MODE_CBC, iv=iv)
        cipher_text = tdes.encrypt(pad(plain_text, DES3.block_size))
        return nonce, iv, cipher_text
    else:
        iv = get_random_bytes(AES_IV_SIZE)
        aes = AES.new(h_key, AES.MODE_CBC, iv)
        cipher_text = aes.encrypt(pad(plain_text, AES.block_size))
        return nonce, iv, cipher_text


def main():
    parser = argparse.ArgumentParser(description="Generator of tests for study protocol")
    parser.add_argument("key", help="Key for cipher, length = 8 bytes")
    parser.add_argument("hash", choices=['md5', 'sha1'], help="Hash function for HMAC")
    parser.add_argument("cipher", choices=['3des', 'aes128', 'aes192', 'aes256'], help='Encryption algorythm')
    args = parser.parse_args()
    key = bytes.fromhex(args.key)
    if len(key) != KEY_SIZE:
        raise Exception(f"Incorrect size of key! Entered key = {key.hex()}")
    hash_fun = args.hash
    cipher = args.cipher
    text = open('./Jane-Eyre.txt', 'rb').read(4096)
    nonce, iv, cipher_text = encrypt(text, key, hash_fun, cipher)
    filename = './enc/' + hash_fun + '_' + cipher + '_' + args.key + '.enc'
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'wb') as file:
        file.write("ENC".encode('ascii'))
        if hash_fun == 'md5':
            file.write(b'\x00')
        else:
            file.write(b'\x01')
        match cipher:
            case '3des':
                file.write(b'\x00')
            case 'aes128':
                file.write(b'\x01')
            case 'aes192':
                file.write(b'\x02')
            case 'aes256':
                file.write(b'\x03')
        file.write(nonce)
        file.write(iv)
        file.write(cipher_text)


if __name__ == '__main__':
    try:
        main()
    except Exception as msg:
        print(msg)
