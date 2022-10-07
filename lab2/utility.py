from bitarray import bitarray


def invert_bits(data: bytearray) -> bytearray:
    bits = bitarray()
    bits.frombytes(data)
    bits.reverse()
    return bytearray(bits.tobytes())


def xor(x: bytearray, y: bytearray) -> bytearray:
    if len(x) != len(y):
        raise Exception("Unequal lengths of arguments for XOR! {0}, {1}".format(len(x), len(y)))
    z = bytearray()
    for i in range(0, len(x)):
        z.append(x[i] ^ y[i])
    return z