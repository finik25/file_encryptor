import unittest
import os
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
        """Тестирование без лишних сообщений о сохранении"""
        password = "test_password"
        key, iv = generate_key(password)
        test_results = {}

        print("\n🔍 Тестирование файлов:")
        for filename in os.listdir(self.test_data_dir):
            file_path = os.path.join(self.test_data_dir, filename)
            if not os.path.isfile(file_path):
                continue

            with self.subTest(file=filename):
                try:
                    # Пути
                    encrypted_path = os.path.join(self.encrypted_dir, f"{filename}.enc")
                    decrypted_path = os.path.join(self.decrypted_dir, filename)

                    # Шифрование (без вывода о сохранении)
                    original_data = read_file(file_path)
                    encrypted_data = encrypt(original_data, key, iv)
                    write_file(encrypted_path, encrypted_data)  # silent mode

                    # Дешифрование (без вывода о сохранении)
                    decrypted_data = decrypt(encrypted_data, key, iv)
                    write_file(decrypted_path, decrypted_data)  # silent mode

                    # Проверка
                    is_success = original_data == decrypted_data
                    test_results[filename] = "✅ УСПЕХ" if is_success else "❌ ОШИБКА"
                    self.assertTrue(is_success)

                    # Вывод информации
                    print(f"\n📄 Файл: {filename}")
                    print(f"   Оригинал: {os.path.relpath(file_path, self.base_dir)}")
                    print(f"   Зашифрован: {os.path.relpath(encrypted_path, self.base_dir)}")
                    print(f"   Расшифрован: {os.path.relpath(decrypted_path, self.base_dir)}")

                except Exception as e:
                    test_results[filename] = f"❌ ОШИБКА: {str(e)}"
                    raise

        # Вывод результатов
        print("\n📊 Результаты:")
        for filename, result in test_results.items():
            print(f"  {filename}: {result}")

        # Очистка (в конце)
        remove_test_files()


if __name__ == "__main__":
    unittest.main()