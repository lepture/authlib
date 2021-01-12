#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from authlib.consts import version, homepage

setup(
    name='Authlib',
    version=version,
    url=homepage,
    packages=find_packages(include=('authlib', 'authlib.*')),
)
