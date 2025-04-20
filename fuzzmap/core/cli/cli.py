import sys
import asyncio
from .parser import Parser
from ..logging.log import Logger
from ..controller.controller import Controller

class CLI:
    def __init__(self):
        self.parser = Parser()
        self.logger = Logger()

    async def async_run(self):
        """CLI 비동기 실행"""
        try:
            # 인자가 없거나 도움말만 있을 때 배너 표시
            if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
                self.print_banner()
                # 인자가 없는 경우에만 사용법 출력 (도움말은 파서가 처리)
                if len(sys.argv) == 1:
                    self.print_usage()
                    return
                
            args = self.parser.parse_args()
            
            # 대상 URL이 없으면 실행하지 않음
            if not args.target:
                return
            
            controller = Controller(
                target=args.target,
                method=args.method,
                param=args.param,
                recon_param=args.recon_param,
                advanced=args.advanced,
                user_agent=args.user_agent,
                cookies=args.cookies
            )
            results = await controller.async_run()
            
            if results:
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
            import asyncio
            from fuzzmap.core.controller.controller import Controller

            async def main():
                # Test with specific parameters
                fm = Controller(target="http://target.com", method="GET", param=["target_parameter"])
                results = await fm.async_run()
                
                # Test with Parameter Reconnaissance
                fm = Controller(target="http://target.com", recon_param=True)
                results = await fm.async_run()

            asyncio.run(main())

        \033[95m⚙️  Options:\033[0m
            -t, --target      🎯 Target URL to scan
            -m, --method      📡 HTTP method (GET/POST)
            -p, --param       🔍 Parameters to test (comma separated)
            -rp, --recon_param 🔎 Enable parameter reconnaissance
            -a, --advanced    🔬 Enable advanced payload scan
            -ua, --user_agent 🌐 Custom User-Agent string
            -c, --cookies     🍪 Cookies to include (format: name1=value1;name2=value2)
            -v, --verbose     📝 Enable verbose output
            -h, --help        ℹ️  Show this help message

        \033[93m🔔 Note: Use responsibly and only on authorized targets\033[0m
        """
        print(usage)

    def print_results(self, results: dict):
        """결과를 출력합니다"""
        if not results:
            print("\n\033[91m[!] No vulnerabilities found.\033[0m")
            return

        print("\n\033[92m[+] Scan Results:\033[0m")
        
        # 파라미터 정보 출력
        if "parameters" in results:
            print("\n\033[94m[*] Detected Parameters:\033[0m")
            for param in results["parameters"]:
                print(f"  - Name: {param.name}")
                print(f"    Type: {param.param_type}")
                print(f"    Method: {param.method}")
                if param.value:
                    print(f"    Value: {param.value}")
                print()

        # 취약점 결과 출력
        if "vulnerabilities" in results:
            for vuln_type, findings in results["vulnerabilities"].items():
                if findings:  # 결과가 있는 경우만 출력
                    print(f"\n\033[94m[*] {vuln_type.upper()} Test Results:\033[0m")
                    for param, param_findings in findings.items():
                        print(f"\n  Parameter: {param}")
                        for finding in param_findings:
                            print(f"    - Payload: {finding.get('payload', 'N/A')}")
                            print(f"      Type: {finding.get('type', 'N/A')}")
                            print(f"      Description: {finding.get('description', 'N/A')}")

def main_entry():
    """진입점 함수"""
    try:
        cli = CLI()
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # 비동기 실행 처리
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(cli.async_run())
        
        # 종료 코드 처리
        return 0 if results else 1
    except KeyboardInterrupt:
        print("\n\033[93m[!] 사용자에 의해 중단되었습니다.\033[0m")
        return 1
    except Exception as e:
        print(f"\n\033[91m[!] 오류 발생: {str(e)}\033[0m")
        return 1

if __name__ == "__main__":
    c = CLI()
    c.print_banner()
    c.print_usage()