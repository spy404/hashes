MOD_ADLER = 65521


def adler32(plain_text: str) -> int:
    a = 1
    b = 0
    for plain_chr in plain_text:
        a = (a + ord(plain_chr)) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    return (b << 16) | a
