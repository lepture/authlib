.. _spec/oidc:

OpenID Connect 1.0
==================

This part of the documentation covers the specification of OpenID Connect.

1. http://openid.net/specs/openid-connect-core-1_0.html


OpenID Grants
-------------

.. module:: authlib.specs.oidc.grants

.. autoclass:: OpenIDCodeGrant
    :show-inheritance:
    :members:

.. autoclass:: OpenIDImplicitGrant
    :show-inheritance:
    :members:

.. autoclass:: OpenIDHybridGrant
    :show-inheritance:
    :members:

OpenID Claims
-------------

.. module:: authlib.specs.oidc

.. autoclass:: IDToken
    :show-inheritance:
    :members:


.. autoclass:: CodeIDToken
    :show-inheritance:
    :members:


.. autoclass:: ImplicitIDToken
    :show-inheritance:
    :members:


.. autoclass:: HybridIDToken
    :show-inheritance:
    :members:
