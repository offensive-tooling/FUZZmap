import argparse

class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="FUZZmap - Web Application Offensive Fuzzing Module"
        )
        self._add_arguments()

    def _add_arguments(self):
        self.parser.add_argument(
            "-t", "--target",
            help="대상 URL",
            required=True
        )
        self.parser.add_argument(
            "-m", "--method",
            help="HTTP 메소드 (GET/POST)",
            choices=['GET', 'POST'],
            default='GET'
        )
        self.parser.add_argument(
            "-p", "--param",
            help="테스트할 파라미터 (쉼표로 구분)",
            type=str
        )
        self.parser.add_argument(
            "-rp", "--recon-param",
            help="파라미터 자동 탐지 활성화",
            action="store_true"
        )
        self.parser.add_argument(
            "-v", "--verbose",
            help="상세 출력 활성화",
            action="store_true"
        )

    def parse_args(self):
        args = self.parser.parse_args()
        if args.param:
            args.param = [p.strip() for p in args.param.split(',')]
        return args 