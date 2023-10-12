def fletcher16(text: str) -> int:
    data = bytes(text, "ascii")
    sum1 = 0
    sum2 = 0
    for character in data:
        sum1 = (sum1 + character) % 255
        sum2 = (sum1 + sum2) % 255
    return (sum2 << 8) | sum1


if __name__ == "__main__":
    import doctest

    doctest.testmod()
