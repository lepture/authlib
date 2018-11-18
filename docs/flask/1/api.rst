API References of Flask OAuth 1.0 Server
========================================

This part of the documentation covers the interface of Flask OAuth 1.0
Server.

.. module:: authlib.flask.oauth1

.. autoclass:: AuthorizationServer
    :members:

.. autoclass:: ResourceProtector
    :member-order: bysource
    :members:

.. data:: current_credential

    Routes protected by :class:`ResourceProtector` can access current credential
    with this variable.

Cache Helper Functions
----------------------

.. module:: authlib.flask.oauth1.cache

.. autofunction:: create_exists_nonce_func

.. autofunction:: register_nonce_hooks

.. autofunction:: register_temporary_credential_hooks

SQLAlchemy Help Functions
-------------------------

.. module:: authlib.flask.oauth1.sqla

.. autofunction:: create_query_client_func

.. autofunction:: create_query_token_func

.. autofunction:: create_exists_nonce_func

.. autofunction:: register_nonce_hooks

.. autofunction:: register_temporary_credential_hooks

.. autofunction:: register_token_credential_hooks
