import os

def read_file(file_path: str) -> bytes:
    """Чтение файла в бинарном режиме."""
    with open(file_path, "rb") as f:
        return f.read()

def write_file(file_path: str, data: bytes, verbose=False):
    """Запись файла с опциональным выводом"""
    try:
        with open(file_path, "wb") as f:
            f.write(data)
        if verbose:  # Выводим только в ручном режиме
            print(f"Файл сохранён: {os.path.abspath(file_path)}")
    except Exception as e:
        raise IOError(f"Ошибка записи файла: {str(e)}")