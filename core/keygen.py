def generate_key(password: str, key_size: int = 32) -> tuple:
    """Генерация ключа и IV из пароля"""

    def simple_hash(data: bytes) -> int:
        hash_val = 0
        for byte in data:
            hash_val = (hash_val * 31 + byte) & 0xFFFFFFFF
        return hash_val

    key_material = bytearray()
    for i in range(key_size + 16):  # Ключ + IV
        seed = simple_hash(f"{password}_{i}".encode())
        val = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        key_material.extend(val.to_bytes(4, 'little'))

    key = bytes(key_material[:key_size])
    iv = bytes(key_material[key_size:key_size + 16])
    return key, iv


def generate_sbox(key_part: bytes, size: int = 256) -> list:
    """Генерация S-box на основе части ключа"""
    sbox = list(range(size))
    seed = int.from_bytes(key_part[:4], 'little')
    for i in range(size - 1, 0, -1):
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        j = seed % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def generate_pbox(key_part: bytes, size: int = 64) -> list:
    """Генерация таблицы перестановок"""
    pbox = list(range(size))
    seed = int.from_bytes(key_part[:4], 'little')
    for i in range(size - 1, 0, -1):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        j = seed % (i + 1)
        pbox[i], pbox[j] = pbox[j], pbox[i]
    return pbox