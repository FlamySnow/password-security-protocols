import argparse
from gen import generate_keys, adjust_key_size, generate_iv
from Crypto.Cipher import AES, DES3
from Crypto.Hash import MD5, SHA1, HMAC
from Crypto.Util.Padding import unpad
import multiprocessing as mp

d = '0123456789'
s = 'abcdefghijklmnopqrstuvwxyz'
l = s.upper()
a = ''.join([d, s, l])


def decrypt(data: bytes, psw: bytes, hf: str, cph: str, ni: bytes, nr: bytes, gx: bytes, gy: bytes, ci: bytes,
            cr: bytes, gxy: bytes) -> (bytes, bytes):
    if cph == '3des':
        cipher = DES3
    else:
        cipher = AES
    skeyid, skeyid_e = generate_keys(psw, hf, ni, nr, gxy, ci, cr)
    skeyid_e = adjust_key_size(skeyid_e, cph, hf)
    iv = generate_iv(hf, cph, gx, gy)
    pt = cipher.new(skeyid_e, cipher.MODE_CBC, iv).decrypt(data)
    try:
        pt = unpad(pt, cipher.block_size)
        return pt, skeyid
    except Exception:
        return None, skeyid


def check(pt: bytes, hf: str, key: bytes, gx: bytes, gy: bytes, ci: bytes, cr: bytes, sa: bytes) -> bool:
    if pt[:2] != b'\x08\x00':
        return False
    if hf == 'md5':
        hash_func = MD5
        hash_size = 16
    else:
        hash_func = SHA1
        hash_size = 20
    id_b = pt[2:len(pt) - hash_size]
    h = pt[len(pt) - hash_size:]
    expected = HMAC.new(key, b''.join([gx, gy, ci, cr, sa, id_b]), hash_func).digest()
    if expected == h:
        return True
    return False


def process(data: bytes, word: str, candidates: list, hf: str, cph: str, ni: bytes, nr: bytes, gx: bytes, gy: bytes,
            ci: bytes, cr: bytes, gxy: bytes, sa: bytes, event):
    if event.is_set():
        return
    print(word)
    while candidates[-1][1] < len(candidates[-1][0]):
        candidate = [x[0][x[1]] for x in candidates]
        password = (word + ''.join(candidate)).encode()
        print(password.decode())
        pt, key = decrypt(data, password, hf, cph, ni, nr, gx, gy, ci, cr, gxy)
        for i in range(len(candidates)):
            if candidates[i][1] < len(candidates[i][0]) - 1:
                candidates[i][1] += 1
                break
            else:
                if i != len(candidates) - 1:
                    candidates[i][1] = 0
                else:
                    candidates[i][1] += 1
        if pt is None:
            continue
        if check(pt, hf, key, gx, gy, ci, cr, sa):
            event.set()
            print(pt)
            return password, pt
    for m in candidates:
        m[1] = 0


def main():
    parser = argparse.ArgumentParser(description="Software for password recovery for the protocol IKEv1 Main Mode")
    parser.add_argument("-d", required=True, help="Dictionary for possible password variants")
    parser.add_argument("-m", required=True, help="Mask for possible password variants")
    parser.add_argument("file", help="File with known data")
    args = parser.parse_args()
    with open(args.d, 'r') as f:
        words = f.read().splitlines()
    mask = args.m
    with open(args.file, 'r') as f:
        data = f.read().split('*')
    match data[0]:
        case '1':
            hash_name = 'md5'
        case '2':
            hash_name = 'sha1'
        case _:
            raise Exception("Incorrect hash id")
    match data[1]:
        case '5':
            cipher = '3des'
        case '7':
            cipher = 'aes128'
        case '8':
            cipher = 'aes192'
        case '9':
            cipher = 'aes256'
        case _:
            raise Exception("Incorrect algorythm id")
    temp = []
    for m in mask:
        match m:
            case 'a':
                temp.append([list(a), 0])
            case 's':
                temp.append([list(s), 0])
            case 'l':
                temp.append([list(l), 0])
            case 'd':
                temp.append([list(d), 0])
            case _:
                raise Exception("Invalid symbols for mask!")
    with mp.Manager() as manager:
        event = manager.Event()
        with mp.Pool(mp.cpu_count() - 1) as p:
            x = [(bytes.fromhex(data[10]), w, temp, hash_name, cipher, bytes.fromhex(data[2]),
                  bytes.fromhex(data[3]), bytes.fromhex(data[4]), bytes.fromhex(data[5]), bytes.fromhex(data[7]),
                  bytes.fromhex(data[8]), bytes.fromhex(data[6]), bytes.fromhex(data[9]), event) for w in words]
            res = p.starmap_async(process, x)
            cand = res.get()
            for p in cand:
                if p is not None:
                    print(f"Password: {p[0].decode()}")
                    print(f"PT: {p[1].hex()}")
                    return
        print("Key is not found")


if __name__ == '__main__':
    try:
        main()
    except Exception as msg:
        print(msg)