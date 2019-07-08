# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os
import io
from setuptools import setup, find_packages

import pymerkle

current_dir = os.path.abspath(os.path.dirname(__file__))

try:
  with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as _file:
    long_description = '\n' + _file.read()
except FileNotFoundError:
    long_description = str()

try:
  with io.open(os.path.join(current_dir, 'requirements.txt'), encoding='utf-8') as _file:
    install_requires = [_.strip() for _ in _file.readlines()]
except FileNotFoundError:
    install_requires = [
      'pytest',
      'pytest-benchmark',
      'tqdm'
]

python_requires = '>=3.6'

setup(
    name="pymerkle",
    version=pymerkle.__version__,
    author="FoteinosMerg",
    author_email="foteinosmerg@protonmail.com",
    description="A Python library for constructing Merkle Trees and validating Log Proofs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://github.com/FoteinosMerg/pymerkle",
    packages=find_packages(exclude=('tests', 'benchmarks')),
    python_requires=python_requires,
    install_requires=install_requires,
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
