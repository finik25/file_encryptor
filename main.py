import argparse
import os
import re
from core.cipher import encrypt_with_metadata, decrypt_with_metadata
from core.keygen import generate_key
from core.file_io import read_file, write_file


def get_project_root():
    """Возвращает абсолютный путь к корневой директории проекта"""
    return os.path.dirname(os.path.abspath(__file__))


def resolve_input_path(input_path: str, target_dir: str = None) -> str:
    """
    Находит файл по возможным путям с учётом кросс-платформенности
    Args:
        input_path: Входной путь (может быть относительным/абсолютным)
        target_dir: Целевая директория для поиска (опционально)
    Returns:
        Абсолютный путь к найденному файлу
    Raises:
        FileNotFoundError: Если файл не найден
    """
    project_root = get_project_root()
    input_path = os.path.normpath(input_path)

    possible_paths = []

    # 1. Абсолютный путь
    if os.path.isabs(input_path):
        possible_paths.append(input_path)

    # 2. Относительный путь от корня проекта
    possible_paths.append(os.path.join(project_root, input_path))

    # 3. В указанной целевой директории
    if target_dir:
        possible_paths.append(
            os.path.join(project_root, target_dir, os.path.basename(input_path))
        )

    # 4. Стандартные директории проекта
    possible_paths.extend([
        os.path.join(project_root, "test_data", os.path.basename(input_path)),
        os.path.join(project_root, "encrypted", os.path.basename(input_path)),
        os.path.join(project_root, "decrypted", os.path.basename(input_path))
    ])

    for path in dict.fromkeys(possible_paths):
        if os.path.exists(path):
            return path

    checked_paths = [os.path.relpath(p, project_root) for p in possible_paths]
    raise FileNotFoundError(
        f"Файл '{input_path}' не найден. Проверялись:\n" +
        "\n".join(f" - {p}" for p in checked_paths)
    )


def validate_filename(name: str) -> str:
    """Очистка имени файла от недопустимых символов"""
    return re.sub(r'[^\w\-_.]', '_', name)[:100]


def encrypt_file(input_path: str, password: str, output_name: str = None, hide_name: bool = False) -> bool:
    try:
        project_root = get_project_root()
        file_path = resolve_input_path(input_path, "test_data")
        print(f"[SEARCH] Найден файл: {os.path.relpath(file_path, project_root)}")

        data = read_file(file_path)
        key, iv = generate_key(password)

        # Сохраняем расширение отдельно
        original_ext = os.path.splitext(file_path)[1]
        encrypted = encrypt_with_metadata(data, file_path, key, iv, hide_name)

        encrypted_dir = os.path.join(project_root, "encrypted")
        os.makedirs(encrypted_dir, exist_ok=True)

        if output_name:
            output_filename = validate_filename(output_name)
            if not output_filename.endswith('.enc'):
                output_filename += '.enc'
        else:
            if hide_name:
                output_filename = "encrypted_data.enc"
            else:
                base_name = os.path.basename(file_path)
                output_filename = f"{base_name}.enc" if not base_name.endswith('.enc') else base_name

        output_path = os.path.join(encrypted_dir, output_filename)
        write_file(output_path, encrypted)

        print(f"[OK] Успешно зашифрован: {os.path.relpath(output_path, project_root)}")
        print(f"[PATH] Полный путь: {output_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Ошибка: {str(e)}")
        return False


def decrypt_file(input_path: str, password: str) -> bool:
    try:
        project_root = get_project_root()
        file_path = resolve_input_path(input_path, "encrypted")
        print(f"[SEARCH] Найден файл: {os.path.relpath(file_path, project_root)}")

        data = read_file(file_path)
        key, iv = generate_key(password)
        metadata, decrypted = decrypt_with_metadata(data, key, iv)

        decrypted_dir = os.path.join(project_root, "decrypted")
        os.makedirs(decrypted_dir, exist_ok=True)

        if 'original_name' in metadata:
            # Если имя не скрыто
            output_filename = metadata['original_name']
        else:
            # Если имя скрыто, используем "decrypted" + оригинальное расширение
            output_filename = "decrypted" + metadata.get('original_ext', '')

        output_path = os.path.join(decrypted_dir, output_filename)
        write_file(output_path, decrypted)

        print(f"[OK] Успешно расшифрован: {os.path.relpath(output_path, project_root)}")
        if 'original_name' in metadata:
            print(f"[INFO] Оригинальное имя: {metadata['original_name']}")
        print(f"[INFO] Размер файла: {metadata['file_size']} байт")
        print(f"[PATH] Полный путь: {output_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Ошибка: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Утилита для шифрования файлов (Windows/Linux)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "mode",
        choices=["encrypt", "decrypt"],
        help="Режим работы:\n  encrypt - шифрование файла\n  decrypt - дешифрование файла"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Путь к файлу\nПримеры:\n  test_data/plaintext.txt\n  encrypted/file.enc"
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Пароль для шифрования/дешифрования"
    )
    parser.add_argument(
        "--output",
        help="Кастомное имя зашифрованного файла (без расширения)"
    )
    parser.add_argument(
        "--hide-name",
        action="store_true",
        help="Скрыть оригинальное имя файла"
    )

    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.file, args.password, args.output, args.hide_name)
    elif args.mode == "decrypt":
        decrypt_file(args.file, args.password)


if __name__ == "__main__":
    main()