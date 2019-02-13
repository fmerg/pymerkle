#!/usr/bin/env python
from setuptools import setup, find_packages
import pymerkle

with open("README.md", "r") as f:
    long_description = f.read()

python_requires='>=3.6'

setup(
    name="pymerkle",
    version=pymerkle.__version__,
    author="Foteinos Mergoupis",
    author_email="foteinosmerg@gmail.com",
    description="A Python library for constructing Merkle Trees and validating Log Proofs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://github.com/FoteinosMerg/pymerkle",
    packages=find_packages(),
    install_requires=open("requirements.txt").readlines(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    license="License :: OSI Approved :: MIT License",
    keywords="merkle proof audit consistency log security encryption")
