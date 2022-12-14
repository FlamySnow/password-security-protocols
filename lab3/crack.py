import argparse
from verifier import verify
from gen import NONCE_SIZE, TDES_IV_SIZE, AES_IV_SIZE, KEY_SIZE, generate_key, PADDING
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad
import multiprocessing as mp
import time


def decrypt(ct: bytes, password: bytes, hash_fun: str, cipher: str, nonce: bytes, iv: bytes):
    key = generate_key(password, nonce, hash_fun, cipher)
    if cipher == '3des':
        in_key = DES3.adjust_key_parity(key)
        tdes = DES3.new(in_key, DES3.MODE_CBC, iv=iv)
        pt = unpad(tdes.decrypt(ct), DES3.block_size)
        return pt[len(PADDING):]
    else:
        aes = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(aes.decrypt(ct), AES.block_size)
        return pt[len(PADDING):]


def print_speed(start, end, t1, t2):
    speed = (end - start) / (t2 - t1)
    print(f'Current: {hex(start)}-{hex(end)}, speed = {speed} c/s')


def generate_candidates(start: int, end: int, password: bytes, v: bool, event):
    if event.is_set():
        return
    start_t = time.time()
    while not event.is_set():
        for i in range(start, end):
            candidate = i.to_bytes(KEY_SIZE, 'big')
            if candidate == password:
                event.set()
                if v:
                    end_t = time.time()
                    print_speed(start, i, start_t, end_t)
                return candidate
    if v:
        end_t = time.time()
        print_speed(start, end, start_t, end_t)


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
    with mp.Manager() as manager:
        event = manager.Event()
        with mp.Pool(mp.cpu_count() - 1) as p:
            step = 2 ** 32 // (mp.cpu_count() * 8)
            ranges = [(a, b, parole, v, event) for a, b in
                      zip(range(0, 2 ** 32 - step, step), range(step, 2 ** 32, step))]
            start = time.time()
            res = p.starmap_async(generate_candidates, ranges)
            cand = res.get()
            t = time.time() - start
            speed = 2 ** 32 / t
            for key in cand:
                if key is not None:
                    print(f'Found: {key.hex()}, average speed = {speed} c/s')
                    pt = decrypt(cipher_text, key, hash_func, cipher, nonce, iv)
                    print(f'Plain text: {pt.decode()}')


if __name__ == '__main__':
    try:
        main()
    except Exception as msg:
        print(msg)
