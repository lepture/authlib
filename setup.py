#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup

rsa_require = ['cryptography', 'pyjwt>=1.0.0']
flask_require = ['Flask']
django_require = ['Django']


def fread(filename):
    with open(filename) as f:
        return f.read()


setup(
    name='Authlib',
    version='0.1rc0',
    author='Hsiaoming Yang',
    author_email='me@lepture.com',
    url='',
    packages=[],
    description=(
        'A ready to use authentication library for '
        'OAuth1, OAuth2 and more.'
    ),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=fread('description.rst'),
    license='LGPLv3',
    install_requires=['requests'],
    extras_require={
        'rsa': rsa_require,
        'flask': flask_require,
        'django': django_require
    },
    classifiers=[
        'Development Status :: 1 - Planning',
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
