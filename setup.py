from setuptools import setup, find_packages
from core.utils import *

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    py_modules=['loxs'],
    name="loxs",
    version="2.1",
    description="Multi Vulnerability Scanner for Web Applications (LFI, OR, SQLi, XSS, CRLF)",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="AnonKryptiQuz, Coffinxp, HexShad0w, Naho, 1hehaq, Hghost010",
    url="https://github.com/coffinxp/loxs",
    packages=find_packages(include=["core*", "scanners*", "*"]),
    include_package_data=True,
    install_requires=[
        "requests>=2.28.1",
        "selenium>=4.10.0",
        "webdriver_manager>=4.0.1",
        "colorama>=0.4.6",
        "rich>=13.5.2",
        "prompt_toolkit>=3.0.36",
        "pyyaml>=6.0",
        "beautifulsoup4>=4.12.2",
        "aiohttp>=3.8.4",
        "Flask>=2.2.3",
        "gitpython>=3.1.32",
        "urllib3>=1.26.16",
        "setuptools"
    ],
    python_requires=">=3.7",
    entry_points={
        'console_scripts': [
            'loxs = loxs:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    project_urls={
        'Documentation': 'https://github.com/coffinxp/loxs',
        'Source': 'https://github.com/coffinxp/loxs',
        'Bug Tracker': 'https://github.com/coffinxp/loxs/issues',
    },
)

if __name__ == "__main__":
    clear_screen()
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Chrome and ChromeDriver are required for XSS/OR scanners.{Style.RESET_ALL}\n")
    print("If not already installed, download Chrome from:")
    print(f"{Fore.GREEN}→{Style.RESET_ALL} {Fore.CYAN}https://www.google.com/chrome/{Style.RESET_ALL}")
    print("ChromeDriver will be automatically managed by webdriver_manager, but you can manually download from:")
    print(f"{Fore.GREEN}→{Style.RESET_ALL} {Fore.CYAN}https://chromedriver.chromium.org/downloads{Style.RESET_ALL}\n")
    print("For Linux, you may need:")
    print(f"{Fore.GREEN}→{Style.RESET_ALL} {Fore.RED}sudo apt install -y wget unzip{Style.RESET_ALL}\n")
    print("Refer to the README for full installation instructions.")
    print(f"{Fore.GREEN}→{Style.RESET_ALL} {Fore.CYAN}https://github.com/coffinxp/loxs/blob/main/README.md{Style.RESET_ALL}")
