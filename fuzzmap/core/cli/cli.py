import sys
from .parser import Parser
from ..logging.log import Logger
from ..controller.controller import Controller

class CLI:
    def __init__(self):
        self.parser = Parser()
        self.logger = Logger()

    def run(self):
        try:
            args = self.parser.parse_args()
            controller = Controller(
                target=args.target,
                method=args.method,
                param=args.param,
                recon_param=args.recon_param
            )
            results = controller.run()
            self.print_results(results)
            return results
        except Exception as e:
            self.logger.error(f"CLI 실행 중 오류 발생: {str(e)}")
            sys.exit(1)

    @staticmethod
    def print_banner():
        """FUZZmap 로고와 버전 정보를 출력합니다"""
        banner = """
        \033[94m
        ███████╗██╗   ██╗███████╗███████╗███╗   ███╗ █████╗ ██████╗ 
        ██╔════╝██║   ██║╚══███╔╝╚══███╔╝████╗ ████║██╔══██╗██╔══██╗
        █████╗  ██║   ██║  ███╔╝   ███╔╝ ██╔████╔██║███████║██████╔╝
        ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║╚██╔╝██║██╔══██║██╔═══╝ 
        ██║     ╚██████╔╝███████╗███████╗██║ ╚═╝ ██║██║  ██║██║     
        ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
        \033[0m
        \033[93m[ 🔍 FUZZmap v0.1 - Web Vulnerability Fuzzer 🎯 ]\033[0m
        \033[96m[ 🛡️  Intelligent Fuzzing & Security Analysis Tool 🔒 ]\033[0m
        
        \033[90m[ Developed with 💻 by:
        🔹 arrester  🔹 jhanks  🔹 mathe  🔹 arecia  🔹 hansowon ]\033[0m
        
        \033[95m[ 🚀 Ready to Hunt Vulnerabilities 🎮 ]\033[0m
        
        \033[92m[ 📦 GitHub: https://github.com/offensive-tooling/fuzzmap ]\033[0m
        """
        print(banner)

    @staticmethod
    def print_usage():
        """사용법을 출력합니다"""
        usage = """
        \033[95m🔧 도구로 사용하는 경우:\033[0m
            fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m get -p cat
            fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m get -p cat,test
            fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m post -p cat
            fuzzmap -t http://testphp.vulnweb.com/listproducts.php -m post -p cat,test
            fuzzmap -t http://testphp.vulnweb.com/listproducts.php -rp

        \033[95m🐍 모듈로 사용하는 경우:\033[0m
            from fuzzmap import Controller

            fm = Controller(target="http://testphp.vulnweb.com",method="GET",param="cat")
            fm.run()

            fm = Controller(target="http://testphp.vulnweb.com",recon_param=True)
            fm.run()

        \033[95m⚙️  Options:\033[0m
            -t, --target    🎯 Target URL to scan
            -m, --method    📡 HTTP method (GET/POST)
            -p, --param     🔍 Parameters to test (comma separated)
            -rp, --recon    🔎 Enable parameter reconnaissance
            -v, --verbose   📝 Enable verbose output
            -h, --help      ℹ️  Show this help message

        \033[93m🔔 Note: Use responsibly and only on authorized targets\033[0m
        """
        print(usage)

    def print_results(self, results: dict):
        """결과를 출력합니다"""
        if not results:
            print("\n\033[91m[!] No vulnerabilities found.\033[0m")
            return

        print("\n\033[92m[+] Scan Results:\033[0m")
        for vuln_type, findings in results.items():
            print(f"\n\033[94m[*] {vuln_type.upper()}:\033[0m")
            for finding in findings:
                print(f"  - Parameter: {finding['param']}")
                print(f"    Payload: {finding['payload']}")
                print(f"    Evidence: {finding['evidence']}")

if __name__ == "__main__":
    c = CLI()
    c.print_banner()
    c.print_usage()