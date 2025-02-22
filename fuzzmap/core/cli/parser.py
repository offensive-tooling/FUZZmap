import argparse

class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="\033[96m🛡️ FUZZmap - Web Vulnerability Fuzzer\033[0m"
        )
        self._add_arguments()

    def _add_arguments(self):
        self.parser.add_argument(
            "-t", "--target",
            help="🎯 Target URL to scan",
            required=True
        )
        self.parser.add_argument(
            "-m", "--method",
            help="📡 HTTP method (GET/POST)",
            default="GET",
            choices=["GET", "POST"],
            type=str.upper
        )
        self.parser.add_argument(
            "-p", "--param",
            help="🔍 Parameters to test (comma separated)",
            type=str
        )
        self.parser.add_argument(
            "-rp", "--recon_param",
            help="🔎 Enable parameter reconnaissance",
            action="store_true"
        )
        self.parser.add_argument(
            "-v", "--verbose",
            help="📝 Enable verbose output",
            action="store_true"
        )

    def parse_args(self):
        args = self.parser.parse_args()
        if args.param:
            args.param = [p.strip() for p in args.param.split(",")]
        return args 