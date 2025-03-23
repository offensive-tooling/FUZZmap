from setuptools import setup, find_packages
import os
import subprocess
import sys


# Playwright 설치를 위한 post-install 스크립트
class PostInstallCommand:
    """Playwright 설치를 위한 post-install 명령 클래스"""

    def run(self):
        try:
            print("\033[94m[*] Playwright 브라우저 설치 시작...\033[0m")
            subprocess.check_call([sys.executable, "-m", "playwright", "install"])
            print("\033[92m[+] Playwright 브라우저 설치 완료!\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Playwright 브라우저 자동 설치 실패: {e}\033[0m")
            print("\033[93m[!] 다음 명령을 수동으로 실행해 주세요: 'playwright install'\033[0m")


# 패키지 설치 후 Playwright 설치 실행
def post_install():
    """패키지 설치 후 자동으로 실행될 함수"""
    PostInstallCommand().run()


# CLI 진입점 함수
def main():
    """명령줄 도구 진입점"""
    try:
        # fuzzmap.core.cli.cli 모듈 동적 임포트
        from fuzzmap.core.cli.cli import CLI
        import asyncio

        cli = CLI()
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # 비동기 실행 처리
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(cli.async_run())
        
        return 0 if results else 1
    except KeyboardInterrupt:
        print("\n\033[93m[!] 사용자에 의해 중단되었습니다.\033[0m")
        return 1
    except Exception as e:
        print(f"\n\033[91m[!] 오류 발생: {str(e)}\033[0m")
        return 1


# 버전 정보 로드
version = "0.1.7"

# 각종 설명 및 메타데이터
description = "FUZZmap is a web application vulnerability fuzzing tool designed to detect security flaws."
long_description = ""

# README.md 파일이 있으면 읽기
if os.path.exists("README.md"):
    with open("README.md", encoding='utf-8') as f:
        long_description = f.read()

setup(
    name="FUZZmap",
    version=version,
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "aiohttp>=3.7.4",
        "beautifulsoup4>=4.9.3",
        "playwright>=1.49.1",
        "argparse"
    ],
    entry_points={
        "console_scripts": [
            "fuzzmap=setup:main",
        ],
        "distutils.commands": [
            "post_install=setup:post_install",
        ],
    },
    author="Offensive Tooling",
    author_email="arresterloyal@gmail.com",
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/offensive-tooling/FUZZmap",
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

# 직접 실행 시 자동으로 post-install 실행
if __name__ == "__main__" and "install" in sys.argv:
    try:
        # 설치 후 실행될 코드
        from setuptools.command.install import install
        
        original_install = install.run
        
        def custom_install(self):
            original_install(self)
            self.execute(post_install, (), msg="Running post-install script...")
        
        install.run = custom_install
    except Exception:
        print("\033[93m[!] 패키지 설치 후 'playwright install' 명령을 실행해 주세요\033[0m") 
