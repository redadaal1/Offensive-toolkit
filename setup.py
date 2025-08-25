#!/usr/bin/env python3
"""
Setup script for Offensive Security Automation Toolkit
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="offsec-toolkit",
    version="1.0.0",
    author="Offsec Team",
    author_email="team@offsec-toolkit.com",
    description="A comprehensive penetration testing automation toolkit",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/offsec-toolkit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "flake8>=5.0.0",
            "black>=22.0.0",
            "mypy>=1.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "offsec=cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.md", "*.txt", "*.html", "*.css"],
    },
    keywords="security penetration-testing automation reconnaissance exploitation",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/offsec-toolkit/issues",
        "Source": "https://github.com/yourusername/offsec-toolkit",
        "Documentation": "https://offsec-toolkit.readthedocs.io/",
    },
) 