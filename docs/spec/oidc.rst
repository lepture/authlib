OpenID Connect
==============

This part of the documentation covers the specification of OpenID Connect.

1. http://openid.net/specs/openid-connect-core-1_0.html

.. module:: authlib.specs.oidc


Shortcut Functions
------------------

Some easy to use functions for parsing and validating id_token JWS text.

.. autofunction:: parse_id_token

.. autofunction:: validate_id_token

.. autofunction:: verify_id_token


ID Token
--------

.. autoclass:: IDToken
   :members:


.. autoclass:: CodeIDToken
   :members:


.. autoclass:: ImplicitIDToken
   :members:


.. autoclass:: HybridIDToken
   :members:
