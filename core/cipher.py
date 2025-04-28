import os


def pad_data(data: bytes, block_size: int = 8) -> bytes:
    """Добавление PKCS7 padding"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_data(data: bytes) -> bytes:
    """Удаление PKCS7 padding"""
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def generate_sbox(key_part: bytes) -> list:
    """Генерация S-box 8x8 (256 элементов)"""
    sbox = list(range(256))
    seed = int.from_bytes(key_part[:4], 'little')

    for i in range(255, 0, -1):
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        j = seed % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]

    return sbox


def generate_pbox(key_part: bytes) -> list:
    """Генерация P-box (перестановка 64 бит)"""
    pbox = list(range(64))
    seed = int.from_bytes(key_part[:4], 'little')

    for i in range(63, 0, -1):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        j = seed % (i + 1)
        pbox[i], pbox[j] = pbox[j], pbox[i]

    return pbox


def apply_pbox(block: bytes, pbox: list) -> bytes:
    """Применение перестановки битов"""
    bits = ''.join(f'{byte:08b}' for byte in block)
    permuted = ''.join(bits[i] for i in pbox)
    return bytes(int(permuted[i:i + 8], 2) for i in range(0, 64, 8))


def apply_sbox(block: bytes, sbox: list) -> bytes:
    """Применение таблицы замен"""
    return bytes(sbox[byte] for byte in block)


def encrypt_block(block: bytes, sboxes: list, pboxes: list) -> bytes:
    """Шифрование одного блока (8 байт)"""
    # Первый раунд
    block = apply_pbox(block, pboxes[0])
    block = apply_sbox(block, sboxes[0])

    # Второй раунд
    block = apply_pbox(block, pboxes[1])
    block = apply_sbox(block, sboxes[1])

    return block


def decrypt_block(block: bytes, sboxes: list, pboxes: list) -> bytes:
    """Дешифрование одного блока (8 байт)"""
    # Обратные S-box
    inv_sboxes = [
        [sboxes[0].index(i) for i in range(256)],
        [sboxes[1].index(i) for i in range(256)]
    ]

    # Обратные P-box
    inv_pboxes = [
        [pboxes[0].index(i) for i in range(64)],
        [pboxes[1].index(i) for i in range(64)]
    ]

    # Раунды в обратном порядке
    block = apply_sbox(block, inv_sboxes[1])
    block = apply_pbox(block, inv_pboxes[1])

    block = apply_sbox(block, inv_sboxes[0])
    block = apply_pbox(block, inv_pboxes[0])

    return block


def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Шифрование данных с CBC режимом"""
    sboxes = [generate_sbox(key[:16]), generate_sbox(key[16:])]
    pboxes = [generate_pbox(key[:8]), generate_pbox(key[8:16])]

    data = pad_data(data)
    blocks = [data[i:i + 8] for i in range(0, len(data), 8)]
    encrypted = bytearray()
    prev_block = iv

    for block in blocks:
        # CBC режим
        block = bytes(b1 ^ b2 for b1, b2 in zip(block, prev_block))
        encrypted_block = encrypt_block(block, sboxes, pboxes)
        encrypted.extend(encrypted_block)
        prev_block = encrypted_block

    return bytes(encrypted)


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Дешифрование данных с CBC режимом"""
    sboxes = [generate_sbox(key[:16]), generate_sbox(key[16:])]
    pboxes = [generate_pbox(key[:8]), generate_pbox(key[8:16])]

    blocks = [data[i:i + 8] for i in range(0, len(data), 8)]
    decrypted = bytearray()
    prev_block = iv

    for block in blocks:
        decrypted_block = decrypt_block(block, sboxes, pboxes)
        # CBC режим
        decrypted_block = bytes(b1 ^ b2 for b1, b2 in zip(decrypted_block, prev_block))
        decrypted.extend(decrypted_block)
        prev_block = block

    return unpad_data(bytes(decrypted))