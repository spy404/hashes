import argparse
import hashlib  # hashlib is only used inside the Test class
import struct


class SHA1Hash:
    """
    >>> SHA1Hash(bytes('Allan', 'utf-8')).final_hash()
    '872af2d8ac3d8695387e7c804bf0e02c18df9e6e'
    """

    def __init__(self, data):
        self.data = data
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    @staticmethod
    def rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def padding(self):
        padding = b"\x80" + b"\x00" * (63 - (len(self.data) + 8) % 64)
        padded_data = self.data + padding + struct.pack(">Q", 8 * len(self.data))
        return padded_data

    def split_blocks(self):
        return [
            self.padded_data[i : i + 64] for i in range(0, len(self.padded_data), 64)
        ]

    # @staticmethod
    def expand_block(self, block):
        w = list(struct.unpack(">16L", block)) + [0] * 64
        for i in range(16, 80):
            w[i] = self.rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
        return w

    def final_hash(self):
        self.padded_data = self.padding()
        self.blocks = self.split_blocks()
        for block in self.blocks:
            expanded_block = self.expand_block(block)
            a, b, c, d, e = self.h
            for i in range(80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                a, b, c, d, e = (
                    self.rotate(a, 5) + f + e + k + expanded_block[i] & 0xFFFFFFFF,
                    a,
                    self.rotate(b, 30),
                    c,
                    d,
                )
            self.h = (
                self.h[0] + a & 0xFFFFFFFF,
                self.h[1] + b & 0xFFFFFFFF,
                self.h[2] + c & 0xFFFFFFFF,
                self.h[3] + d & 0xFFFFFFFF,
                self.h[4] + e & 0xFFFFFFFF,
            )
        return ("{:08x}" * 5).format(*self.h)


def test_sha1_hash():
    msg = b"Test String"
    assert SHA1Hash(msg).final_hash() == hashlib.sha1(msg).hexdigest()  # noqa: S324


def main():
    # unittest.main()
    parser = argparse.ArgumentParser(description="Process some strings or files")
    parser.add_argument(
        "--string",
        dest="input_string",
        default="Hello World!! Welcome to Cryptography",
        help="Hash the string",
    )
    parser.add_argument("--file", dest="input_file", help="Hash contents of a file")
    args = parser.parse_args()
    input_string = args.input_string
    # In any case hash input should be a bytestring
    if args.input_file:
        with open(args.input_file, "rb") as f:
            hash_input = f.read()
    else:
        hash_input = bytes(input_string, "utf-8")
    print(SHA1Hash(hash_input).final_hash())


if __name__ == "__main__":
    main()
    import doctest

    doctest.testmod()
