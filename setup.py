#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from authlib.consts import name, version, homepage


with open('README.rst') as f:
    readme = f.read()


client_requires = ['requests']
crypto_requires = ['cryptography']


setup(
    name=name,
    version=version,
    author='Quartic.ai Engineering Team',
    author_email='tech@quartic.ai',
    url=homepage,
    packages=find_packages(include=('authlib', 'authlib.*')),
    description=(
        'The ultimate Python library in building OAuth and '
        'OpenID Connect servers.'
    ),
    include_package_data=True,
    long_description=readme,
    install_requires=crypto_requires,
    extras_require={
        'client': client_requires,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
