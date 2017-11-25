#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
from authlib.consts import version, homepage

rsa_require = ['cryptography', 'pyjwt>=1.0.0']
flask_require = ['Flask']
django_require = ['Django']


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
        'A ready to use authentication library for '
        'OAuth1, OAuth2, OpenID connect and more.'
    ),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=fread('README.rst'),
    license='LGPLv3',
    install_requires=['requests'],
    extras_require={
        'rsa': rsa_require,
        'flask': flask_require,
        'django': django_require
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
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
