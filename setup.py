from setuptools import setup, find_packages

setup(
    name="fuzzmap",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.1",
        "pytest>=6.2.4",
    ],
) 