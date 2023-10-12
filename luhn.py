from __future__ import annotations


def is_luhn(string: str) -> bool:
    check_digit: int
    _vector: list[str] = list(string)
    __vector, check_digit = _vector[:-1], int(_vector[-1])
    vector: list[int] = [int(digit) for digit in __vector]

    vector.reverse()
    for i, digit in enumerate(vector):
        if i & 1 == 0:
            doubled: int = digit * 2
            if doubled > 9:
                doubled -= 9
            check_digit += doubled
        else:
            check_digit += digit

    return check_digit % 10 == 0


if __name__ == "__main__":
    import doctest

    doctest.testmod()
    assert is_luhn("79927398713")
    assert not is_luhn("79927398714")
