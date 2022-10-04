from Crypto.Hash import SHA512
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.Hash import MD4
from Crypto.Hash import MD5
import os


def hash_function(func):
    match func:
        case 'sha-512':
            return SHA512
        case 'sha-256':
            return SHA256
        case 'sha-1':
            return SHA1
        case 'md5':
            return MD5
        case 'md4':
            return MD4
        case _:
            raise Exception("Unsupported hash function")


def calculate(value, func):
    hash_ = hash_function(func)
    result = hash_.new()
    result.update(value)
    return result.digest()


def check_values(data, hash_values, enc, func):
    print("Process {}:".format(os.getpid()))
    for x in data:
        x_hash = calculate(x, func)
        for value in hash_values:
            if x_hash == value:
                print("Password '{0}' matches hash '{1}'".format(x.decode(enc), value.hex()))
