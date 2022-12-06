import argparse
from Crypto.Hash import MD5, SHA1, HMAC
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad

COOKIE_I = b'\xc1\xae\x2e\x73\x24\x61\xdd\xcc'
COOKIE_R = b'\xf8\x2a\x8c\x31\x1e\x1a\x3e\xb7'
NONCE_I = b'\x0f\x20\x62\x8a\xa4\xef\xd7\xb9\x2c\xa9\x55\x43\x80\xa7\x12\xa1\x86\xcf\x99\xfe\xdd\xf3\x6a\x9a\x30\x03' \
          b'\xa5\xa6\x8a\xd6\xf7\x49'
NONCE_R = b'\x8a\x94\x4e\x96\x36\x30\xca\xce\x46\xd8\x7b\xaa\x6f\x99\x5b\xd2\x53\xeb\x9a\x80\xcf\xf8\xf0\xf9\xa1\xbd' \
          b'\xdd\x4d\x17\x32\xc3\x7c'
G_X = bytes.fromhex("a4ba2df0fc47dbf5d57883140a8289c15a7423bdf0c6f2e2d039a123719d6957def99b1b4372cdebdc055ad164ea218488"
                    "85191a8b59ac46cd382294e598fae71013869659835db2ae69f616689c751ce03d3e7c0ea1c8d99daaacf652d5ed089483"
                    "87aa3d39695be4914bdf425de692060c9fb35ea1e387a9b54dcc02ac0af5")
G_Y = bytes.fromhex("538d6bde8d6d566bc03445eec118a7d18fe58d4d4f766d6157a295ce5474f1fdacc00c073412da2b5af93ada36e696daa3"
                    "2c62a3ab9548cf0c67f2d387f473ae79f9465dbb3c7703b265c6b3bf5ca6182b1dd35107e940efdddea7011a3bcc0ef4b3"
                    "1ef06125cdeda02a96157a7232153405b8918f1be0c18fb0cb3f338ce564")
G_XY = bytes.fromhex("5795c69c8fe8802204fcd52077f899be0fa439579e39b773084508c25ae68a95b2a2dcbac4fdd293dd9cb9dca684c6902"
                     "c3b9a0e47d4791dc9dc408be0e58564121a1a44388e2885b1940865740868ad4a934ef95a144c47e4cb061c907bfbf8a1"
                     "611dca168bfb4e74fd65a61545612be0f2d93f0baa42272822893056e99b96")

SAI = bytes.fromhex("00000001000000010000002c000100010000002400010000800b0001800c0e1080010007800e0080800200028003000180"
                    "040002")

# ID = b'\x08\x00\x00\x0c\x01\x11\x00\x00\xc0\xa8\x0c\x02'

ID_B = b'\x01\x11\x00\x00\xc0\xa8\x0c\x02'


def adjust_key_size(key: bytes, cph: str, hf: str) -> bytes:
    match cph:
        case 'aes128':
            key_size = 16
        case 'aes256':
            key_size = 32
        case _:
            key_size = 24
    if len(key) == key_size:
        return key
    if hf == 'md5':
        h = MD5
    else:
        h = SHA1
    if len(key) < key_size:
        k0 = HMAC.new(key, b'\x00', h).digest()
        ka = k0
        while len(ka) < key_size:
            k0 = HMAC.new(key, k0, h).digest()
            ka = b''.join([ka, k0])
        key = ka
    if len(key) > key_size:
        key = key[:key_size]
    return key


def generate_keys(psw: bytes, hf: str, ni: bytes, nr: bytes, gxy: bytes, ci: bytes, cr: bytes) -> (bytes, bytes):
    if hf == 'md5':
        hash_function = MD5
    else:
        hash_function = SHA1
    skeyid = HMAC.new(psw, b''.join([ni, nr]), hash_function).digest()
    skeyid_d = HMAC.new(psw, b''.join([gxy, ci, cr, b'\x00']), hash_function).digest()
    skeyid_a = HMAC.new(psw, b''.join([skeyid_d, gxy, ci, cr, b'\x01']), hash_function).digest()
    skeyid_e = HMAC.new(psw, b''.join([skeyid_a, gxy, ci, cr, b'\x02']), hash_function).digest()
    return skeyid, skeyid_e


def encrypt(psw: bytes, hf: str, cph: str, ni=NONCE_I, nr=NONCE_R, gx=G_X, gy=G_Y, ci=COOKIE_I, cr=COOKIE_R, sa=SAI,
            idi_b=ID_B, gxy=G_XY) -> bytes:
    if hf == 'md5':
        hash_function = MD5
    else:
        hash_function = SHA1
    if cph == '3des':
        cipher = DES3
        iv_size = 8
    else:
        cipher = AES
        iv_size = 16
    skeyid, skeyid_e = generate_keys(psw, hf, ni, nr, gxy, ci, cr)
    skeyid_e = adjust_key_size(skeyid_e, cph, hf)
    print(len(skeyid_e))
    hash_i = HMAC.new(skeyid, b''.join([gx, gy, ci, cr, sa, idi_b]), hash_function).digest()
    pt = b''.join([b'\x08\x00', idi_b, b'\x00\x00', hash_i])
    iv = hash_function.new(b''.join([gx, gy])).digest()
    if len(iv) > iv_size:
        iv = iv[:iv_size]
    return cipher.new(skeyid_e, cipher.MODE_CBC, iv).encrypt(pad(pt, cipher.block_size))


def main():
    parser = argparse.ArgumentParser(description="Generator of tests for software for password recovery in protocol IKE"
                                                 "Main Mode")
    parser.add_argument("-H", choices=["md5", "sha1"], required=True, help="Hash function")
    parser.add_argument("-a", choices=["3des", "aes128", "aes192", "aes256"], required=True,
                        help="Encryption algorythm")
    parser.add_argument("-p", required=True, help="Password")
    args = parser.parse_args()
    hash_name = args.H
    cipher_name = args.a
    password = args.p.encode()
    ek = encrypt(password, hash_name, cipher_name)
    with open(f'{args.p}_{hash_name}_{cipher_name}.txt', 'w') as file:
        if hash_name == 'md5':
            hash_id = 1
        else:
            hash_id = 2
        match cipher_name:
            case '3des':
                alg_id = 5
            case 'aes128':
                alg_id = 7
            case 'aes192':
                alg_id = 8
            case _:
                alg_id = 9
        file.write(f'{hash_id}*{alg_id}*{NONCE_I.hex()}*{NONCE_R.hex()}*{G_X.hex()}*{G_Y.hex()}*{G_XY.hex()}*'
                   f'{COOKIE_I.hex()}*{COOKIE_R.hex()}*{SAI.hex()}*{ek.hex()}')


if __name__ == '__main__':
    main()
