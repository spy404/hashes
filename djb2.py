def djb2(s: str) -> int:
    hash_value = 5381
    for x in s:
        hash_value = ((hash_value << 5) + hash_value) + ord(x)
    return hash_value & 0xFFFFFFFF
