.. _specs/oidc:

OpenID Connect 1.0
==================

.. meta::
    :description: General implementation of OpenID Connect 1.0 in Python.
        Learn how to create a OpenID Connect provider in Python.

This part of the documentation covers the specification of OpenID Connect. Learn
how to use it in :ref:`flask_odic_server`.

OpenID Grants
-------------

.. module:: authlib.oidc.core.grants

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

.. module:: authlib.oidc.core

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
