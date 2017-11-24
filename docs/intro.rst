.. _intro:

Introduction
============

Authlib is a ready to use library for authentication. It was designed to be a
replacement for my Flask-OAuthlib project. Later it becomes a :ref:`monolithic`
project that powers from low-level specification implementation to high-level
framework integrations.

I'm intended to make it profitable, so that it can be :ref:`sustainable`.

.. _monolithic:

Monolithic
----------

Authlib is a monolithic library. While being monolithic, it keeps everything
synchronized, from spec implementation to framework integrations, from client
requests to server providers.

The benefits are obvious, it won't break things. When specifications changed,
implementation will change too. Let the developers of Authlib take the pain,
users of Authlib should not suffer from it.

You don't have to worry about monolithic, it doesn't cost your memory. If
you don't import a module, it won't be loaded. We don't madly import everything
into the root **__init__.py**.

Specification
-------------

Authlib is a spec-compliant library which follows the latest specifications.
We keep the generic tool functions in a ``specs`` module. When there is a
related specification, we add it into ``specs``.

Currently, these specs are in the warehouse:

* RFC5849 :ref:`specs/rfc5849`
* RFC6749 :ref:`specs/rfc6749`
* RFC6750 :ref:`specs/rfc6750`
* RFC7009 :ref:`specs/rfc7009`
* RFC7662 :ref:`specs/rfc7662`

Credits
-------

This project is inspired by:

* OAuthLib
* Flask-OAuthlib
* requests-oauthlib

And many codes come from these three projects.

Authlib License
---------------

Authlib is licensed under LGPLv3. But there is a commercial license under
`Authlib Plus <https://authlib.org/plans>`_ plan.
