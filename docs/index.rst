.. Authlib documentation master file, created by
   sphinx-quickstart on Wed Nov  1 11:04:52 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Authlib: Ready to use Authentication
====================================

Release v\ |version|. (:ref:`Installation <install>`)

Authlib is a ready to use authentication library. It is designed from low level
APIs to high level APIs, to meet the needs of everyone.


Features
--------

Lovely features that Authlib has built-in:

- Generic specification implementations
- OAuth 1 (RFC5849)
- OAuth 2 (RFC6749, RFC6750, RFC7009, RFC7662)
- OpenID Connect
- OAuth 1, OAuth 2 Requests Sessions
- Mixed OAuth 1 and OAuth 2 Client
- Integrated client with Flask
- Integrated client with Django
- **TODO** Flask OAuth 1 Server
- Flask OAuth 2 Authorization server and resource protector
- **TODO** Django OAuth 1 / OAuth 2 Servers

Authlib is compatible with Python2.7+ and Python3.5+.

User Guide
----------

This part of the documentation begins with some background information
about Authlib, and information on the client parts.

.. toctree::
   :maxdepth: 2

   intro
   install
   client/oauth1
   client/oauth2
   client/mixed
   client/frameworks
   client/apps

Server Guide
------------

This part of the documentation contains information on the server parts.

.. toctree::
   :maxdepth: 2

   flask/oauth2

.. note:: Django support will be added later.

Specifications
--------------

Guide on specifications. You don't have to read this section if you are
just using Authlib. But it would be good for you to understand how Authlib
works.

(Under Construction)

.. toctree::
   :maxdepth: 2

   spec/rfc5849
   spec/rfc6749
   spec/rfc6750
   spec/rfc7009
   spec/rfc7662
   spec/oidc

Community & Contribution
------------------------

This section aims to make Authlib sustainable, on governance, code commits,
issues and finance.

.. toctree::
   :maxdepth: 2

   community/support
   community/security
   community/contribute
   community/awesome
   community/sustainable
   community/authors

API Reference
-------------

If you are looking for information on a specific function, class or method,
this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api/client
   api/misc

Get Updates
-----------

Stay tuned with Authlib, here is a history of Authlib changes.

.. toctree::
   :maxdepth: 2

   changelog


.. admonition:: Subscribe the Newsletter

   Here is a NEWSLETTER for you: https://tinyletter.com/authlib
