import argparse
import time
from Crypto.Cipher import AES, DES3
from Crypto.Hash import MD5, SHA1, HMAC
import multiprocessing as mp
import test_hmac
import test_sha1

OPTIMIZED = True
TEST = True

d = '0123456789'
s = 'abcdefghijklmnopqrstuvwxyz'
l = s.upper()
a = ''.join([d, s, l])


def opt_hmac(key, data):
    inner, outer = test_sha1.Sha1Hash().get_init_hash(key)
    i_hash = test_sha1.Sha1Hash().process_rest(data, inner).opt_digest()
    return test_sha1.Sha1Hash().process_rest(i_hash, outer).opt_digest()


def adjust_key_size(key: bytes, cph: str, hf: str) -> bytes:
    match cph:
        case 'aes192':
            key_size = 24
        case 'aes256':
            key_size = 32
        case _:
            key_size = 16
    if len(key) == key_size:
        return key
    if hf == 'md5':
        h = MD5
    else:
        h = SHA1
    if len(key) < key_size:
        if TEST:
            if OPTIMIZED:
                k0 = opt_hmac(key, b'\x00')
            else:
                k0 = test_hmac.HMAC(key, b'\x00', test_sha1.Sha1Hash).digest()
        else:
            k0 = HMAC.new(key, b'\x00', h).digest()
        ka = k0
        while len(ka) < key_size:
            if TEST:
                if OPTIMIZED:
                    k0 = opt_hmac(key, k0)
                else:
                    k0 = test_hmac.HMAC(key, k0, test_sha1.Sha1Hash).digest()
            else:
                k0 = HMAC.new(key, k0, h).digest()
            ka = b''.join([ka, k0])
        key = ka
    if len(key) > key_size:
        key = key[:key_size]

    # if len(key) < key_size:
    #     k_1 = HMAC.new(key, b'\x00', h).digest()
    #     k_2 = HMAC.new(key, k_1, h).digest()
    #     k = k_1 + k_2
    #     return k[: key_size]
    # elif len(key) > key_size:
    #     return key[:key_size]

    return key


def generate_keys(psw: bytes, hf: str, ni: bytes, nr: bytes, gxy: bytes, ci: bytes, cr: bytes) -> (bytes, bytes):
    if hf == 'md5':
        hash_function = MD5
    else:
        hash_function = SHA1
    if TEST:
        if OPTIMIZED:
            skeyid = opt_hmac(psw, b''.join([ni, nr]))
            skeyid_d = opt_hmac(skeyid, b''.join([gxy, ci, cr, b'\x00']))
            skeyid_a = opt_hmac(skeyid, b''.join([skeyid_d, gxy, ci, cr, b'\x01']))
            skeyid_e = opt_hmac(skeyid, b''.join([skeyid_a, gxy, ci, cr, b'\x02']))
        else:
            skeyid = test_hmac.new(psw, b''.join([ni, nr]), test_sha1.Sha1Hash).digest()
            skeyid_d = test_hmac.new(skeyid, b''.join([gxy, ci, cr, b'\x00']), test_sha1.Sha1Hash).digest()
            skeyid_a = test_hmac.new(skeyid, b''.join([skeyid_d, gxy, ci, cr, b'\x01']), test_sha1.Sha1Hash).digest()
            skeyid_e = test_hmac.new(skeyid, b''.join([skeyid_a, gxy, ci, cr, b'\x02']), test_sha1.Sha1Hash).digest()
    else:
        skeyid = HMAC.new(psw, b''.join([ni, nr]), hash_function).digest()
        skeyid_d = HMAC.new(skeyid, b''.join([gxy, ci, cr, b'\x00']), hash_function).digest()
        skeyid_a = HMAC.new(skeyid, b''.join([skeyid_d, gxy, ci, cr, b'\x01']), hash_function).digest()
        skeyid_e = HMAC.new(skeyid, b''.join([skeyid_a, gxy, ci, cr, b'\x02']), hash_function).digest()
    return skeyid, skeyid_e


def generate_iv(hf: str, cph: str, gx: bytes, gy: bytes) -> bytes:
    if hf == 'md5':
        hash_func = MD5
    else:
        hash_func = SHA1
    if cph == '3des':
        size = 8
    else:
        size = 16
    iv = hash_func.new(b''.join([gx, gy])).digest()
    if len(iv) > size:
        iv = iv[:size]
    return iv


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
    return pt, skeyid


def check(pt: bytes, hf: str, key: bytes, gx: bytes, gy: bytes, ci: bytes, cr: bytes, sa: bytes) -> bool:
    if pt[:4] != b'\x08\x00\x00\x0c':
        return False
    if hf == 'md5':
        hash_func = MD5
        hash_size = 16
    else:
        hash_func = SHA1
        hash_size = 20
    id_b = pt[4: pt[3]]
    h = pt[pt[3] + 4: pt[3] + hash_size + 4]
    if TEST:
        if OPTIMIZED:
            expected = opt_hmac(key, b''.join([gx, gy, ci, cr, sa, id_b]))
        else:
            expected = test_hmac.new(key, b''.join([gx, gy, ci, cr, sa, id_b]), test_sha1.Sha1Hash).digest()
    else:
        expected = HMAC.new(key, b''.join([gx, gy, ci, cr, sa, id_b]), hash_func).digest()
    if expected == h:
        print(f"ID: {id_b.hex()}")
        print(f"HASH: {h.hex()}")
        return True
    return False


def process(data: bytes, word: str, candidates: list, hf: str, cph: str, ni: bytes, nr: bytes, gx: bytes, gy: bytes,
            ci: bytes, cr: bytes, gxy: bytes, sa: bytes, event):
    if event.is_set():
        return
    count = 0
    while candidates[-1][1] < len(candidates[-1][0]) and not event.is_set():
        count += 1
        candidate = [x[0][x[1]] for x in candidates]
        password = (word + ''.join(candidate)).encode()
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
            print(f"Password: {password.decode()}")
            return password, count
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
    if TEST and hash_name != "sha1":
        raise Exception("Unsupported mode for optimization testing!")
    with mp.Manager() as manager:
        event = manager.Event()
        with mp.Pool(mp.cpu_count() - 2) as p:
            x = [(bytes.fromhex(data[10]), w, temp, hash_name, cipher, bytes.fromhex(data[2]),
                  bytes.fromhex(data[3]), bytes.fromhex(data[4]), bytes.fromhex(data[5]), bytes.fromhex(data[7]),
                  bytes.fromhex(data[8]), bytes.fromhex(data[6]), bytes.fromhex(data[9]), event) for w in words]
            start = time.time()
            res = p.starmap_async(process, x).get()
            time_ = time.time() - start
            for r in res:
                if r is not None:
                    passw, count = r
                    word = passw.decode()[:-len(mask)]
                    word_index = words.index(word)
                    mask_len = 1
                    for t in temp:
                        mask_len *= len(t[0])
                    num = word_index * mask_len + count
                    speed = num/time_
                    print(f"Time: {time_} s Speed: {speed} c/s")


if __name__ == '__main__':
    try:
        main()
    except Exception as msg:
        print(msg)
