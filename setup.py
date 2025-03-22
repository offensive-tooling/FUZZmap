from setuptools import setup, find_packages

setup(
    name="FUZZmap",
    version="0.1.6",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "beautifulsoup4",
        "playwright",
        "argparse"
    ],
    entry_points={
        "console_scripts": [
            "fuzzmap=fuzzmap.fuzzmap:main",
        ],
    },
    author="Offensive Tooling",
    author_email="",
    description="Web Application Offensive Fuzzing Module",
    long_description=open("README.md", encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/offensive-tooling/FUZZmap",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
) 
