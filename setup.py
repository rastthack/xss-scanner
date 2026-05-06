from setuptools import setup, find_packages

setup(
    name="xss-scanner",
    version="2.0",
    description="Advanced XSS Vulnerability Scanner for authorized penetration testing",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.28",
        "beautifulsoup4>=4.11",
        "lxml>=4.9",
        "colorama>=0.4",
    ],
    entry_points={
        "console_scripts": [
            "xss-scanner=xss_scanner.main:main",
        ]
    },
)
