import logging
import os
from datetime import datetime

class Logger:
    def __init__(self):
        self.setup_logging()

    def setup_logging(self):
        # INFO 로그 설정
        info_log_dir = "core/logging/INFO"
        os.makedirs(info_log_dir, exist_ok=True)
        info_handler = logging.FileHandler(
            f"{info_log_dir}/INFO_logging.log"
        )
        info_handler.setLevel(logging.INFO)

        # ERROR 로그 설정
        error_log_dir = "core/logging/ERROR"
        os.makedirs(error_log_dir, exist_ok=True)
        error_handler = logging.FileHandler(
            f"{error_log_dir}/ERROR_logging.log"
        )
        error_handler.setLevel(logging.ERROR)

        # 로그 포맷 설정
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        info_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)

        # 루트 로거 설정
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(info_handler)
        root_logger.addHandler(error_handler)

    def info(self, message: str):
        logging.info(message)

    def error(self, message: str):
        logging.error(message)

    def warning(self, message: str):
        logging.warning(message)

    def debug(self, message: str):
        logging.debug(message) 