from collections.abc import Generator
from math import sin


def to_little_endian(string_32: bytes) -> bytes:
    if len(string_32) != 32:
        raise ValueError("Input must be of length 32")

    little_endian = b""
    for i in [3, 2, 1, 0]:
        little_endian += string_32[8 * i : 8 * i + 8]
    return little_endian


def reformat_hex(i: int) -> bytes:
    if i < 0:
        raise ValueError("Input must be non-negative")

    hex_rep = format(i, "08x")[-8:]
    little_endian_hex = b""
    for i in [3, 2, 1, 0]:
        little_endian_hex += hex_rep[2 * i : 2 * i + 2].encode("utf-8")
    return little_endian_hex


def preprocess(message: bytes) -> bytes:
    bit_string = b""
    for char in message:
        bit_string += format(char, "08b").encode("utf-8")
    start_len = format(len(bit_string), "064b").encode("utf-8")

    # Pad bit_string to a multiple of 512 chars
    bit_string += b"1"
    while len(bit_string) % 512 != 448:
        bit_string += b"0"
    bit_string += to_little_endian(start_len[32:]) + to_little_endian(start_len[:32])

    return bit_string


def get_block_words(bit_string: bytes) -> Generator[list[int], None, None]:
    if len(bit_string) % 512 != 0:
        raise ValueError("Input must have length that's a multiple of 512")

    for pos in range(0, len(bit_string), 512):
        block = bit_string[pos : pos + 512]
        block_words = []
        for i in range(0, 512, 32):
            block_words.append(int(to_little_endian(block[i : i + 32]), 2))
        yield block_words


def not_32(i: int) -> int:
    if i < 0:
        raise ValueError("Input must be non-negative")

    i_str = format(i, "032b")
    new_str = ""
    for c in i_str:
        new_str += "1" if c == "0" else "0"
    return int(new_str, 2)


def sum_32(a: int, b: int) -> int:
    return (a + b) % 2**32


def left_rotate_32(i: int, shift: int) -> int:
    if i < 0:
        raise ValueError("Input must be non-negative")
    if shift < 0:
        raise ValueError("Shift must be non-negative")
    return ((i << shift) ^ (i >> (32 - shift))) % 2**32


def md5_me(message: bytes) -> bytes:
    # Convert to bit string, add padding and append message length
    bit_string = preprocess(message)

    added_consts = [int(2**32 * abs(sin(i + 1))) for i in range(64)]

    # Starting states
    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    shift_amounts = [
        7,
        12,
        17,
        22,
        7,
        12,
        17,
        22,
        7,
        12,
        17,
        22,
        7,
        12,
        17,
        22,
        5,
        9,
        14,
        20,
        5,
        9,
        14,
        20,
        5,
        9,
        14,
        20,
        5,
        9,
        14,
        20,
        4,
        11,
        16,
        23,
        4,
        11,
        16,
        23,
        4,
        11,
        16,
        23,
        4,
        11,
        16,
        23,
        6,
        10,
        15,
        21,
        6,
        10,
        15,
        21,
        6,
        10,
        15,
        21,
        6,
        10,
        15,
        21,
    ]

    # Process bit string in chunks, each with 16 32-char words
    for block_words in get_block_words(bit_string):
        a = a0
        b = b0
        c = c0
        d = d0

        # Hash current chunk
        for i in range(64):
            if i <= 15:
                # f = (b & c) | (not_32(b) & d)     # Alternate definition for f
                f = d ^ (b & (c ^ d))
                g = i
            elif i <= 31:
                # f = (d & b) | (not_32(d) & c)     # Alternate definition for f
                f = c ^ (d & (b ^ c))
                g = (5 * i + 1) % 16
            elif i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | not_32(d))
                g = (7 * i) % 16
            f = (f + a + added_consts[i] + block_words[g]) % 2**32
            a = d
            d = c
            c = b
            b = sum_32(b, left_rotate_32(f, shift_amounts[i]))

        # Add hashed chunk to running total
        a0 = sum_32(a0, a)
        b0 = sum_32(b0, b)
        c0 = sum_32(c0, c)
        d0 = sum_32(d0, d)

    digest = reformat_hex(a0) + reformat_hex(b0) + reformat_hex(c0) + reformat_hex(d0)
    return digest


if __name__ == "__main__":
    import doctest

    doctest.testmod()
