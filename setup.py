#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages

setup(
    name='Authlib',
    url='https://authlib.org/',
    packages=find_packages(include=('authlib', 'authlib.*')),
)
