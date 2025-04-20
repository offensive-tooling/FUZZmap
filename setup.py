from setuptools import setup, find_packages, Command
import os
import subprocess
import sys


# Playwright 설치를 위한 사용자 정의 설치 명령
class InstallWithPlaywright(Command):
    description = "설치 후 Playwright 브라우저 설치"
    user_options = []
    
    def initialize_options(self):
        pass
        
    def finalize_options(self):
        pass
        
    def run(self):
        try:
            print("\033[94m[*] Playwright 브라우저 설치 시작...\033[0m")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
            subprocess.check_call([sys.executable, "-m", "playwright", "install"])
            print("\033[92m[+] Playwright 브라우저 설치 완료!\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Playwright 브라우저 자동 설치 실패: {e}\033[0m")
            print("\033[93m[!] 다음 명령을 수동으로 실행해 주세요: 'playwright install'\033[0m")


# 버전 정보 로드
version = "0.2"  # 버전 업데이트

# 각종 설명 및 메타데이터
description = "FUZZmap is a web application vulnerability fuzzing tool designed to detect security flaws."
long_description = ""

# README.md 파일이 있으면 읽기
if os.path.exists("README.md"):
    with open("README.md", encoding='utf-8') as f:
        long_description = f.read()

setup(
    name="fuzzmap",
    version=version,
    packages=find_packages(include=['fuzzmap', 'fuzzmap.*', 'fuzzmap.core.*']),
    package_data={
        'fuzzmap': ['core/handler/payloads/*.json', 'core/handler/payloads/**/*.json'],
    },
    include_package_data=True,
    install_requires=[
        "requests>=2.25.0",
        "aiohttp>=3.7.4",
        "beautifulsoup4>=4.9.3",
        "playwright>=1.40.0",
        "argparse"
    ],
    entry_points={
        "console_scripts": [
            "fuzzmap=fuzzmap.__main__:run_main",  # __main__.py의 run_main 함수 참조
        ],
    },
    cmdclass={
        'install_with_playwright': InstallWithPlaywright,
    },
    author="Offensive Tooling (arrester, jhanks, mathe, arecia, hansowon)",
    author_email="arresterloyal@gmail.com",
    maintainer="Offensive Tooling",
    maintainer_email="arresterloyal@gmail.com, jhanks1221@gmail.com, sosoeme8@gmail.com, syuwon2006@gmail.com, hansowon0601@gmail.com",
    project_urls={
        "Homepage": "https://github.com/offensive-tooling/fuzzmap",
        "Bug Tracker": "https://github.com/offensive-tooling/fuzzmap/issues",
        "Documentation": "https://github.com/offensive-tooling/fuzzmap/wiki",
        "Source Code": "https://github.com/offensive-tooling/fuzzmap",
    },
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/offensive-tooling/fuzzmap",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    keywords=["security", "web", "fuzzing", "vulnerability", "scanner"],
    python_requires=">=3.7",
)

# 사용자에게 안내 메시지 출력
if "install" in sys.argv:
    print("\n\033[93m[!] 패키지 설치 완료! 필요한 경우 'playwright install' 명령을 실행하세요.\033[0m")
    print("\033[93m[!] 또는 'python setup.py install_with_playwright' 명령으로 Playwright 브라우저를 설치할 수 있습니다.\033[0m")

# 스크립트가 직접 실행되었을 때 Playwright 설치 안내
if __name__ == "__main__":
    # 설치 후 안내 메시지 출력
    if "install" in sys.argv:
        try:
            # 설치 완료 후 브라우저 설치 시도
            print("\n\033[94m[*] Playwright 브라우저 자동 설치를 시도합니다...\033[0m")
            subprocess.check_call([sys.executable, "-m", "playwright", "install"])
            print("\033[92m[+] Playwright 브라우저 설치 완료!\033[0m")
        except Exception:
            print("\033[93m[!] 자동 설치 실패. 수동으로 'playwright install' 명령을 실행해 주세요.\033[0m") 
