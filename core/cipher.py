import os
import json
import time
import numpy as np
from typing import Tuple, Dict
from functools import lru_cache

# Глобальные переменные для профилирования
encrypt_timings = {}
decrypt_timings = {}


def timed(f):
    """Декоратор для замера времени выполнения функций"""

    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = f(*args, **kwargs)
        elapsed = time.perf_counter() - start

        timings_dict = encrypt_timings if 'encrypt' in f.__name__ else decrypt_timings
        if f.__name__ not in timings_dict:
            timings_dict[f.__name__] = []
        timings_dict[f.__name__].append(elapsed)

        return result

    return wrapper


@lru_cache(maxsize=32)
def get_sbox_cached(key_part: bytes) -> list:
    """Оптимизированное кеширование S-box с lru_cache"""
    sbox = list(range(256))
    seed = int.from_bytes(key_part[:4], 'little')
    for i in range(255, 0, -1):
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        j = seed % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


@lru_cache(maxsize=32)
def get_pbox_cached(key_part: bytes) -> np.ndarray:
    """Генерация P-box с возвратом numpy array"""
    pbox = list(range(64))
    seed = int.from_bytes(key_part[:4], 'little')
    for i in range(63, 0, -1):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        j = seed % (i + 1)
        pbox[i], pbox[j] = pbox[j], pbox[i]
    return np.array(pbox, dtype=np.uint8)


@timed
def pad_data(data: bytes, block_size: int = 8) -> bytes:
    """Добавление PKCS7 padding с замером времени"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


@timed
def unpad_data(data: bytes) -> bytes:
    """Удаление PKCS7 padding с проверкой"""
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


@timed
def apply_sbox_numpy(block: np.ndarray, sbox: np.ndarray) -> np.ndarray:
    """Векторизованное применение S-box через numpy"""
    return sbox[block]


@timed
def apply_pbox_numpy(block: np.ndarray, pbox: np.ndarray) -> np.ndarray:
    """Оптимизированное применение P-box через numpy"""
    bits = np.unpackbits(block)
    permuted = bits[pbox]
    return np.packbits(permuted)


@timed
def encrypt_block_ultra(block: bytes, sboxes: list, pboxes: list) -> bytes:
    """Максимально оптимизированное шифрование блока"""
    block_arr = np.frombuffer(block.ljust(8, b'\x00'), dtype=np.uint8)

    # Применяем преобразования через numpy
    block_arr = apply_sbox_numpy(block_arr, sboxes[0])
    block_arr = apply_pbox_numpy(block_arr, pboxes[0])
    block_arr = apply_sbox_numpy(block_arr, sboxes[1])
    block_arr = apply_pbox_numpy(block_arr, pboxes[1])

    return block_arr.tobytes()[:len(block)]


@timed
def decrypt_block_ultra(block: bytes, inv_sboxes: list, inv_pboxes: list) -> bytes:
    """Оптимизированное дешифрование блока"""
    block_arr = np.frombuffer(block.ljust(8, b'\x00'), dtype=np.uint8)

    # Обратные преобразования
    block_arr = apply_pbox_numpy(block_arr, inv_pboxes[1])
    block_arr = apply_sbox_numpy(block_arr, inv_sboxes[1])
    block_arr = apply_pbox_numpy(block_arr, inv_pboxes[0])
    block_arr = apply_sbox_numpy(block_arr, inv_sboxes[0])

    return block_arr.tobytes()[:len(block)]


@timed
def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Оптимизированное шифрование с предварительными вычислениями"""
    # Кешируем преобразования
    sboxes = [
        np.array(get_sbox_cached(key[:16]), dtype=np.uint8),
        np.array(get_sbox_cached(key[16:]), dtype=np.uint8)
    ]
    pboxes = [
        get_pbox_cached(key[:8]),
        get_pbox_cached(key[8:16])
    ]

    # Подготовка данных
    data_padded = pad_data(data)
    encrypted = bytearray()

    # Обеспечиваем правильный размер IV (8 байт)
    prev_block = np.frombuffer(iv.ljust(8, b'\x00')[:8], dtype=np.uint8)

    # Обрабатываем блоки без использования memoryview
    for i in range(0, len(data_padded), 8):
        block = data_padded[i:i + 8]

        # Дополняем блок до 8 байт и преобразуем в numpy array
        block_padded = block.ljust(8, b'\x00')[:8]
        block_arr = np.frombuffer(block_padded, dtype=np.uint8)

        # CBC через numpy с проверкой размеров
        if block_arr.shape != prev_block.shape:
            block_arr = np.resize(block_arr, prev_block.shape)
        block_arr = np.bitwise_xor(block_arr, prev_block)

        # Шифрование блока
        encrypted_block = encrypt_block_ultra(block_arr.tobytes(), sboxes, pboxes)
        encrypted.extend(encrypted_block)
        prev_block = np.frombuffer(encrypted_block, dtype=np.uint8)

    return bytes(encrypted)


@timed
def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Оптимизированное дешифрование с кешированием"""
    # Подготовка преобразований
    sboxes = [
        np.array(get_sbox_cached(key[:16]), dtype=np.uint8),
        np.array(get_sbox_cached(key[16:]), dtype=np.uint8)
    ]
    pboxes = [
        get_pbox_cached(key[:8]),
        get_pbox_cached(key[8:16])
    ]

    # Кешируем обратные преобразования
    cache_key = (id(sboxes[0]), id(sboxes[1]), id(pboxes[0]), id(pboxes[1]))
    if not hasattr(decrypt, 'cache'):
        decrypt.cache = {}

    if cache_key not in decrypt.cache:
        inv_sboxes = [
            np.array([sboxes[0].tolist().index(i) for i in range(256)], dtype=np.uint8),
            np.array([sboxes[1].tolist().index(i) for i in range(256)], dtype=np.uint8)
        ]
        inv_pboxes = [
            np.array([pboxes[0].tolist().index(i) for i in range(64)], dtype=np.uint8),
            np.array([pboxes[1].tolist().index(i) for i in range(64)], dtype=np.uint8)
        ]
        decrypt.cache[cache_key] = (inv_sboxes, inv_pboxes)

    inv_sboxes, inv_pboxes = decrypt.cache[cache_key]
    decrypted = bytearray()

    # Обеспечиваем правильный размер IV (8 байт)
    prev_block = np.frombuffer(iv.ljust(8, b'\x00')[:8], dtype=np.uint8)

    # Обрабатываем блоки без использования memoryview
    for i in range(0, len(data), 8):
        block = data[i:i + 8]

        # Дешифрование блока
        decrypted_block = decrypt_block_ultra(block, inv_sboxes, inv_pboxes)

        # Дополняем блок до 8 байт и преобразуем в numpy array
        decrypted_block_padded = decrypted_block.ljust(8, b'\x00')[:8]
        decrypted_block_arr = np.frombuffer(decrypted_block_padded, dtype=np.uint8)

        # CBC через numpy с проверкой размеров
        if decrypted_block_arr.shape != prev_block.shape:
            decrypted_block_arr = np.resize(decrypted_block_arr, prev_block.shape)
        decrypted_block_arr = np.bitwise_xor(decrypted_block_arr, prev_block)

        decrypted.extend(decrypted_block_arr.tobytes())
        prev_block = np.frombuffer(block.ljust(8, b'\x00')[:8], dtype=np.uint8)

    return unpad_data(bytes(decrypted))


def print_timings():
    """Вывод статистики по времени выполнения"""

    def print_section(title, timings):
        print(f"\n=== {title} ===")
        total = 0
        for func, times in timings.items():
            func_time = sum(times)
            print(f"{func:25}: {func_time:.4f}s (вызовов: {len(times)})")
            total += func_time
        print(f"Итого: {total:.4f}s")

    print_section("Шифрование", encrypt_timings)
    print_section("Дешифрование", decrypt_timings)


# Функции для работы с метаданными
def pack_metadata(filepath: str, hide_name: bool = False) -> bytes:
    if hide_name:
        metadata = {
            'original_ext': os.path.splitext(filepath)[1],
            'file_size': os.path.getsize(filepath),
            'timestamp': int(os.path.getmtime(filepath))
        }
    else:
        metadata = {
            'original_name': os.path.basename(filepath),
            'file_size': os.path.getsize(filepath),
            'timestamp': int(os.path.getmtime(filepath))
        }
    return json.dumps(metadata).encode('utf-8')


@timed
def encrypt_with_metadata(data: bytes, filepath: str, key: bytes, iv: bytes, hide_name: bool = False) -> bytes:
    """Шифрование с метаданными"""
    metadata = pack_metadata(filepath, hide_name)
    encrypted_meta = encrypt(metadata, key, iv)
    encrypted_data = encrypt(data, key, iv)
    return len(encrypted_meta).to_bytes(4, 'big') + encrypted_meta + encrypted_data


@timed
def decrypt_with_metadata(encrypted_data: bytes, key: bytes, iv: bytes) -> Tuple[Dict, bytes]:
    """Дешифрование с метаданными"""
    meta_len = int.from_bytes(encrypted_data[:4], 'big')
    encrypted_meta = encrypted_data[4:4 + meta_len]
    metadata = json.loads(decrypt(encrypted_meta, key, iv).decode('utf-8'))
    data = decrypt(encrypted_data[4 + meta_len:], key, iv)
    return metadata, data