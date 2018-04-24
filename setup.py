#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from authlib.consts import version, homepage


def fread(filename):
    with open(filename) as f:
        return f.read()


setup(
    name='Authlib',
    version=version,
    author='Hsiaoming Yang',
    author_email='me@lepture.com',
    url=homepage,
    packages=find_packages(exclude=['tests']),
    description=(
        'An ambitious authentication library for OAuth 1, OAuth 2, '
        'OpenID clients and servers.'
    ),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=fread('README.rst'),
    license='AGPLv3+',
    install_requires=['requests', 'cryptography'],
    project_urls={
        'Bug Tracker': 'https://github.com/lepture/authlib/issues',
        'Documentation': 'https://docs.authib.org/',
        'Source Code': 'https://github.com/lepture/authlib',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
