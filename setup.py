#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from authlib.consts import version, homepage


with open('README.rst') as f:
    readme = f.read()


client_requires = ['requests']
crypto_requires = ['cryptography']


setup(
    name='Authlib',
    version=version,
    author='Hsiaoming Yang',
    author_email='me@lepture.com',
    url=homepage,
    packages=find_packages(include=('authlib', 'authlib.*')),
    description=(
        'The ultimate Python library in building OAuth and '
        'OpenID Connect servers.'
    ),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=readme,
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
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
