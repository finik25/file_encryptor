import os
import shutil


def remove_test_files(silent=False):
    """Удаляет тестовые файлы с возможностью тихого режима"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_dirs = [
        os.path.join(base_dir, "tests", "encrypted"),
        os.path.join(base_dir, "tests", "decrypted")
    ]

    removed_files = []
    for dir_path in test_dirs:
        if os.path.exists(dir_path):
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                        removed_files.append(file_path)
                except Exception as e:
                    if not silent:
                        print(f"⚠️ Не удалось удалить {filename}: {e}")

    if not silent and removed_files:
        print("\n🧹 Очистка тестовых файлов:")
        for file in removed_files:
            print(f"  Удалён: {os.path.relpath(file, base_dir)}")