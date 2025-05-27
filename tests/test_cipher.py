import unittest
import os
import time
from core.keygen import generate_key
from core.cipher import encrypt, decrypt
from core.file_io import read_file, write_file
from core.file_remover import remove_test_files


class TestFileEncryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.test_data_dir = os.path.join(cls.base_dir, "test_data")
        cls.encrypted_dir = os.path.join(cls.base_dir, "tests", "encrypted")
        cls.decrypted_dir = os.path.join(cls.base_dir, "tests", "decrypted")

        os.makedirs(cls.encrypted_dir, exist_ok=True)
        os.makedirs(cls.decrypted_dir, exist_ok=True)

    def test_all_files(self):
        password = "test_password"
        key, iv = generate_key(password)
        test_results = {}

        print("\n[SEARCH] Тестирование файлов:")
        for filename in os.listdir(self.test_data_dir):
            file_path = os.path.join(self.test_data_dir, filename)
            if not os.path.isfile(file_path):
                continue

            with self.subTest(file=filename):
                try:
                    encrypted_path = os.path.join(self.encrypted_dir, f"{filename}.enc")
                    decrypted_path = os.path.join(self.decrypted_dir, filename)

                    original_data = read_file(file_path)
                    encrypted_data = encrypt(original_data, key, iv)
                    write_file(encrypted_path, encrypted_data)

                    decrypted_data = decrypt(encrypted_data, key, iv)
                    write_file(decrypted_path, decrypted_data)

                    is_success = original_data == decrypted_data
                    test_results[filename] = "[OK] УСПЕХ" if is_success else "[ERROR] ОШИБКА"
                    self.assertTrue(is_success)

                    print(f"\n[FILE] Файл: {filename}")
                    print(f"   Оригинал: {os.path.relpath(file_path, self.base_dir)}")
                    print(f"   Зашифрован: {os.path.relpath(encrypted_path, self.base_dir)}")
                    print(f"   Расшифрован: {os.path.relpath(decrypted_path, self.base_dir)}")

                except Exception as e:
                    test_results[filename] = f"[ERROR] ОШИБКА: {str(e)}"
                    raise

        print("\n[RESULTS] Результаты:")
        for filename, result in test_results.items():
            print(f"  {filename}: {result}")

        from core.cipher import print_timings
        print_timings()
        remove_test_files()


    def test_speed(self):
        """Тест скорости шифрования/дешифрования с автоматическим выбором самого большого файла"""
        # Находим самый большой файл в тестовой директории
        files = []
        for f in os.listdir(self.test_data_dir):
            file_path = os.path.join(self.test_data_dir, f)
            if os.path.isfile(file_path):
                files.append((file_path, os.path.getsize(file_path)))

        if not files:
            self.skipTest("Тестовые файлы не найдены")

        largest_file = max(files, key=lambda x: x[1])
        file_path, file_size = largest_file

        data = read_file(file_path)
        file_size_mb = file_size / (1024 * 1024)
        print(f"\n[SPEED] Тестируем файл: {os.path.basename(file_path)} ({file_size_mb:.2f} MB)")

        # Тест генерации ключа
        start = time.time()
        key, iv = generate_key("speed_test_password")
        keygen_time = time.time() - start
        print(f"[SPEED] Генерация ключа: {keygen_time:.3f} сек")

        # Тест шифрования
        start = time.time()
        encrypted = encrypt(data, key, iv)
        encrypt_time = time.time() - start
        encrypt_speed = len(data) / encrypt_time / (1024 * 1024)
        print(f"[SPEED] Шифрование: {encrypt_time:.3f} сек ({encrypt_speed:.2f} MB/s)")

        # Тест дешифрования
        start = time.time()
        decrypted = decrypt(encrypted, key, iv)
        decrypt_time = time.time() - start
        decrypt_speed = len(data) / decrypt_time / (1024 * 1024)
        print(f"[SPEED] Дешифрование: {decrypt_time:.3f} сек ({decrypt_speed:.2f} MB/s)")

        # Общая скорость
        total_time = keygen_time + encrypt_time + decrypt_time
        total_speed = len(data) * 2 / total_time / 1024 / 128 # в MBit/s
        print(f"[SPEED] Общая скорость: {total_speed:.2f} MBit/s")

        # Проверка требования (>2 MBit/s)
        self.assertGreater(total_speed, 2,
                           f"Скорость {total_speed:.2f} KB/s ниже требуемых 250 KB/s (2 Mbit/s)")

        # Проверка целостности
        self.assertEqual(data, decrypted, "Ошибка: данные после дешифрования не совпадают")


if __name__ == "__main__":
    unittest.main()