import argparse
from gen import KEY_SIZE

hash_funcs = ['md5', 'sha1']
ciphers = ['3des', 'aes128', 'aes192', 'aes256']


def verify() -> bool:
    parser = argparse.ArgumentParser(description="Verification for files encrypted by study cipher")
    parser.add_argument("file", help="File with extension '.enc'")
    args = parser.parse_args()
    path = args.file
    filename = path.split('\\')[-1]
    unscored = filename.split('_')
    hash_func = unscored[0]
    cipher = unscored[1]
    key = bytes.fromhex(unscored[2][:-4])
    ext = unscored[2][-4:]
    if hash_func not in hash_funcs:
        print(hash_func)
        return False
    if cipher not in ciphers:
        print(cipher)
        return False
    if len(key) != KEY_SIZE:
        print(len(key))
        return False
    if ext != '.enc':
        print(ext)
        return False
    with open(path, 'rb') as file:
        sign = file.read(3).decode('ascii')
        if sign != 'ENC':
            print(sign)
            return False
        hash_byte = file.read(1)
        if hash_byte == b'\x00':
            if hash_func != 'md5':
                return False
        else:
            if hash_byte != b'\x01':
                return False
        cipher_byte = file.read(1)
        match cipher_byte:
            case b'\x00':
                if cipher != '3des':
                    return False
            case b'\x01':
                if cipher != 'aes128':
                    return False
            case b'\x02':
                if cipher != 'aes192':
                    return False
            case _:
                if cipher_byte != '\x03':
                    return False
    return True


if __name__ == '__main__':
    try:
        print(verify())
    except Exception as msg:
        print(msg)
        print(False)
