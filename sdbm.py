def sdbm(plain_text: str) -> int:
    hash_value = 0
    for plain_chr in plain_text:
        hash_value = (
            ord(plain_chr) + (hash_value << 6) + (hash_value << 16) - hash_value
        )
    return hash_value
