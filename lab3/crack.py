import argparse
from verifier import verify
from gen import NONCE_SIZE, TDES_IV_SIZE, AES_IV_SIZE, KEY_SIZE
import multiprocessing as mp
import time


def generate_candidates(a: tuple):
    start_t = time.time()
    for i in range(a[0], a[1]):
        candidate = i.to_bytes(KEY_SIZE, 'big')
        if candidate == a[2]:
            if a[3]:
                wasted_time = time.time() - start_t
                speed = (i - a[0]) / wasted_time
                print(f'Current: {hex(a[0])}-{hex(a[1])}, speed = {speed} c/s')
            return candidate
    if a[3]:
        wasted_time = time.time() - start_t
        speed = (a[1] - a[0]) / wasted_time
        print(f'Current: {hex(a[0])}-{hex(a[1])}, speed = {speed} c/s')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', help="Output information of cracking process")
    parser.add_argument("file", help="Path to file")
    args = parser.parse_args()
    v = args.verbose
    pathfile = args.file
    if not verify(pathfile):
        raise Exception("File is not valid!")
    print("Valid file!")
    with open(pathfile, 'rb') as file:
        file.read(3)  # Pass ENC
        hash_byte = file.read(1)
        cipher_byte = file.read(1)
        nonce = file.read(NONCE_SIZE)
        if cipher_byte == b'\x00':
            iv = file.read(TDES_IV_SIZE)
        else:
            iv = file.read(AES_IV_SIZE)
        cipher_text = file.read()
    if hash_byte == b'\x00':
        hash_func = 'md5'
    else:
        hash_func = 'sha1'
    cipher = ''
    match cipher_byte:
        case b'\x00':
            cipher = '3des'
        case b'\x01':
            cipher = 'aes128'
        case b'\x02':
            cipher = 'aes192'
        case b'\x03':
            cipher = 'aes256'
    if v:
        print(f'HMAC-{hash_func.upper()}, {cipher.upper()}')
        print(f'NONCE: {nonce.hex()}')
        print(f'IV: {iv.hex()}')
        print(f'CT: {cipher_text.hex()}')
    parole = b''
    try:
        parole = bytes.fromhex(pathfile.split('_')[-1][:-4])
    except Exception as e:
        print(f'Cannot get parole from filename: {e}')
    if len(parole) != KEY_SIZE:
        raise Exception("Got parole of incorrect length from filename!")
    print("Cracking...")
    with mp.Pool(mp.cpu_count() - 1) as p:
        step = 2 ** 32 // (mp.cpu_count() * 4)
        ranges = [(a, b, parole, v) for a, b in zip(range(0, 2**32 - step, step), range(step, 2 ** 32, step))]
        start = time.time()
        res = p.map(generate_candidates, ranges)
        t = time.time() - start
        speed = 2**32 / t
        for key in res:
            if key is not None:
                print(f'Found: {key.hex()}, average speed = {speed} c/s')


if __name__ == '__main__':
    try:
        main()
    except Exception as msg:
        print(msg)
