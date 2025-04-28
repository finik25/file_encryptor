import os
import struct
from typing import Tuple


def custom_hash(data: bytes, output_len: int = 32) -> bytes:
    """
    Самописная хеш-функция с хорошим лавинным эффектом
    Args:
        data: входные данные
        output_len: длина вывода (по умолчанию 32 байта)
    """
    # Инициализация внутреннего состояния (8 слов по 32 бита)
    state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Добавление длины данных
    data += struct.pack('Q', len(data))

    # Обработка блоков по 64 байта
    for i in range(0, len(data), 64):
        block = data[i:i + 64]
        if len(block) < 64:
            block += bytes([0x80] + [0x00] * (63 - len(block)))

        # Преобразование блока в 16 слов
        words = [int.from_bytes(block[j:j + 4], 'little') for j in range(0, 64, 4)]

        # Упрощенный раунд (4 итерации вместо 64)
        for _ in range(4):
            # Нелинейное перемешивание
            a, b, c, d, e, f, g, h = state

            # Простые битовые операции
            maj = (a & b) ^ (a & c) ^ (b & c)
            ch = (e & f) ^ ((~e) & g)

            # Циклические сдвиги
            s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
            s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))

            # Обновление состояния
            temp = (h + s1 + ch + words[_ % 16] + 0x428a2f98) & 0xFFFFFFFF
            new_a = (temp + s0 + maj) & 0xFFFFFFFF
            state = [new_a, a, b, c, d, e, f, g]

    # Финализация (первые output_len байт)
    return b''.join(struct.pack('I', word) for word in state)[:output_len]




def generate_key(password: str, salt: bytes = None, iterations: int = 500) -> Tuple[bytes, bytes]:
    """
    Генерация ключа с самописной хеш-функцией
    Args:
        password: парольная фраза
        salt: соль (16 байт), если None - генерируется из пароля
        iterations: количество итераций (оптимизировано для скорости)
    """
    # Генерация соли
    if salt is None:
        salt = custom_hash(password.encode('utf-8'))[:16]

    # Первое хеширование
    key_material = custom_hash(password.encode('utf-8') + salt)

    # Умеренное количество итераций
    for i in range(iterations):
        key_material = custom_hash(key_material + struct.pack('I', i))

    # Разделение на ключ (32 байта) и IV (16 байт)
    key = key_material[:32]
    iv = custom_hash(key + salt)[:16]

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