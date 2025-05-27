import sys
import time
from typing import Callable


class SimpleLogger:
    def __init__(self):
        self.verbose = False
        self.log_file = "crypto_operations.log"  # Файл для записи

    def log(self, message: str, is_debug: bool = False):
        msg = f"[{'DEBUG' if is_debug else 'INFO'}] {message}"
        if self.verbose or not is_debug:
            print(msg)

        # Всегда пишем в лог-файл, даже в не-verbose
        with open(self.log_file, "a") as f:
            f.write(f"{time.ctime()} - {msg}\n")

    def set_verbose(self, enabled: bool):
        self.verbose = enabled

    def error(self, message: str):
        """Вывод ошибок (всегда виден)"""
        print(f"[ERROR] {message}", file=sys.stderr)

# Глобальный экземпляр логгера
logger = SimpleLogger()