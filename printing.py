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

def print_usage():
    """사용법을 출력합니다"""
    usage = """
    \033[95m🔧 Usage:\033[0m
        fuzzmap [options] -u <target-url>

    \033[95m⚙️  Options:\033[0m
        -u, --url       🎯 Target URL to scan
        -p, --param     🔍 Specific parameter to test
        -t, --timeout   ⏱️  Request timeout (default: 30s)
        -v, --verbose   📝 Enable verbose output
        -h, --help      ℹ️  Show this help message

    \033[95m📌 Example:\033[0m
        fuzzmap -u http://example.com/page.php?id=1 -p id

    \033[93m🔔 Note: Use responsibly and only on authorized targets\033[0m

    \033[92m📚 Documentation & Updates:\033[0m
        https://github.com/offensive-tooling/fuzzmap
    """
    print(usage)

if __name__ == "__main__":
    print_banner()
    print_usage()