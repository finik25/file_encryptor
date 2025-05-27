import os
from core.logger import logger

def read_file(file_path: str) -> bytes:
    logger.log(f"Чтение файла: {file_path}", is_debug=True)
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        logger.log(f"Успешно прочитано {len(data)} байт", is_debug=True)
        return data
    except Exception as e:
        logger.error(f"Ошибка чтения: {file_path} - {str(e)}")
        raise

def write_file(file_path: str, data: bytes, verbose=False):
    """Запись файла с опциональным выводом"""
    try:
        with open(file_path, "wb") as f:
            f.write(data)
        if verbose:  # Выводим только в ручном режиме
            print(f"Файл сохранён: {os.path.abspath(file_path)}")
    except Exception as e:
        raise IOError(f"Ошибка записи файла: {str(e)}")