import logging
import os
from datetime import datetime

class Logger:
    def __init__(self):
        self.setup_logging()
        
    def setup_logging(self):
        # 로그 디렉토리 경로 설정
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        log_dir = os.path.join(base_dir, "core/logging")
        
        # INFO 로거 설정
        info_logger = logging.getLogger('info_logger')
        info_logger.setLevel(logging.INFO)
        info_log_dir = os.path.join(log_dir, "INFO")
        os.makedirs(info_log_dir, exist_ok=True)
        info_handler = logging.FileHandler(
            os.path.join(info_log_dir, "INFO_logging.log")
        )
        info_handler.setLevel(logging.INFO)
        info_filter = logging.Filter()
        info_filter.filter = lambda record: record.levelno == logging.INFO
        info_handler.addFilter(info_filter)

        # ERROR 로거 설정
        error_logger = logging.getLogger('error_logger')
        error_logger.setLevel(logging.ERROR)
        error_log_dir = os.path.join(log_dir, "ERROR")
        os.makedirs(error_log_dir, exist_ok=True)
        error_handler = logging.FileHandler(
            os.path.join(error_log_dir, "ERROR_logging.log")
        )
        error_handler.setLevel(logging.ERROR)

        # 로그 포맷 설정
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        info_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)

        # 핸들러 추가
        info_logger.addHandler(info_handler)
        error_logger.addHandler(error_handler)
        
        # 로거 저장
        self.info_logger = info_logger
        self.error_logger = error_logger

    def info(self, message: str):
        self.info_logger.info(message)

    def error(self, message: str):
        self.error_logger.error(message)

    def warning(self, message: str):
        self.error_logger.warning(message)

    def debug(self, message: str):
        self.info_logger.debug(message) 