#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from authlib.consts import version, homepage

client_requires = ['requests']
crypto_requires = ['cryptography>=3.2,<4']


setup(
    name='Authlib',
    version=version,
    url=homepage,
    packages=find_packages(include=('authlib', 'authlib.*')),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    license='BSD-3-Clause',
    install_requires=crypto_requires,
    extras_require={
        'client': client_requires,
    },
    project_urls={
        'Documentation': 'https://docs.authlib.org/',
        'Commercial License': 'https://authlib.org/plans',
        'Bug Tracker': 'https://github.com/lepture/authlib/issues',
        'Source Code': 'https://github.com/lepture/authlib',
        'Blog': 'https://blog.authlib.org/',
        'Donate': 'https://lepture.com/donate',
    },
)
