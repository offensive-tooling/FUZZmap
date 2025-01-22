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
            help="URL과 폼에서 파라미터를 자동으로 탐지합니다. -p 옵션과 함께 사용할 수 없습니다.",
            action="store_true"
        )
        self.parser.add_argument(
            "-v", "--verbose",
            help="상세 출력 활성화",
            action="store_true"
        )

    def parse_args(self):
        args = self.parser.parse_args()
        if args.param and args.recon_param:
            self.parser.error("--param과 --recon-param은 동시에 사용할 수 없습니다.")
        if args.param:
            args.param = [p.strip() for p in args.param.split(',')]
        return args 