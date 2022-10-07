import decryption
import encryption
from encryption import BLOCK_SIZE, generate_keys


def process(data: bytearray, key: bytearray, mode: str, dbg=False, iv=None, enc=True) -> bytearray:
    if len(key) != BLOCK_SIZE:
        raise Exception('Incorrect size of key!')
    data_chunks = [data[i: i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    if len(data_chunks[-1]) != BLOCK_SIZE:
        for i in range(len(data_chunks[-1]), BLOCK_SIZE):
            data_chunks[-1].append(0x00)
    k = generate_keys(key)
    if dbg:
        print("K0: ", k[0].hex())
        print("K1: ", k[1].hex())
        print("K2: ", k[2].hex())
    if mode == 'ecb':
        if enc:
            return encryption.ECB(data_chunks, k, dbg)
        else:
            return decryption.ECB(data_chunks, k, dbg)
    elif mode == 'cbc' and iv is not None:
        iv_b = bytearray.fromhex(iv)
        if len(iv_b) != BLOCK_SIZE:
            raise Exception("Incorrect size of IV!")
        if enc:
            return encryption.CBC(data_chunks, k, iv_b, dbg)
        else:
            return decryption.CBC(data_chunks, k, iv_b, dbg)
    else:
        raise Exception("Incorrect mode of encryption!")