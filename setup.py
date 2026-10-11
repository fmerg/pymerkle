#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import setup, find_packages
import os
import io
import re

homepage = 'https://github.com/fmerg/pymerkle'

current_dir = os.path.abspath(os.path.dirname(__file__))

# Single source of version: parse rather than import the package, which may
# not be importable before its dependencies are installed
with io.open(os.path.join(current_dir, 'pymerkle', '__init__.py'),
    encoding='utf-8') as f:
    version = re.search(r"^__version__ = '([^']+)'", f.read(), re.M).group(1)

try:
  with io.open(os.path.join(current_dir, 'requirements.txt'),
    encoding='utf-8') as f:
    install_requires = [_.strip() for _ in f.readlines()]
except FileNotFoundError:
    install_requires = [
        'cachetools==7.2.1'
    ]

with open('README.md', 'r') as f:
    long_description = f.read()

def main():
    setup(
       name='pymerkle',
       version=version,
       description='Merkle-tree cryptography in python',
       long_description=long_description,
       long_description_content_type='text/markdown',
       packages=find_packages(exclude=['tests']),
       # package_dir={'': 'pymerkle'},
       url=homepage,
       project_urls={
            'github': homepage,
            'source': '%s/%s' % (homepage, 'tree/master/%s' % 'pymerkle'),
            'docs': 'https://pymerkle.readthedocs.io/en/latest/',
       },
       author='fmerg',
       author_email='fmerg@protonmail.com',
       python_requires='>=3.11',
       install_requires=install_requires,
       extras_require={
           'keccak': ['safe-pysha3==1.0.5'],
       },
       zip_safe=False,
       keywords=[
           'merkle', 'proof', 'inclusion', 'consistency',
       ],
       classifiers=[
           'Development Status :: 4 - Beta',
           'Intended Audience :: Developers',
           'Intended Audience :: Science/Research',
           'Programming Language :: Python :: 3',
           'Programming Language :: Python :: 3 :: Only',
           'Programming Language :: Python :: 3.11',
           'Programming Language :: Python :: 3.12',
           'Programming Language :: Python :: 3.13',
           'Programming Language :: Python :: 3.14',
           'Operating System :: POSIX',
           'Topic :: Security :: Cryptography',
           'Topic :: Software Development :: Libraries :: Python Modules',
           'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)'
       ],
    )


if __name__ == '__main__':
    main()
