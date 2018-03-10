Server Reference
================

.. meta::
   :description: API references on Authlib server part, including Flask related integrations.

This part of the documentation covers the interface of Authlib Server.


Flask OAuth 1 Server
--------------------

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
~~~~~~~~~~~~~~~~~~~~~~

.. module:: authlib.flask.oauth1.cache

.. autofunction:: create_exists_nonce_func

.. autofunction:: register_nonce_hooks

.. autofunction:: register_temporary_credential_hooks

SQLAlchemy Help Functions
~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: authlib.flask.oauth1.sqla

.. autofunction:: create_query_client_func

.. autofunction:: create_query_token_func

.. autofunction:: create_exists_nonce_func

.. autofunction:: register_nonce_hooks

.. autofunction:: register_temporary_credential_hooks

.. autofunction:: register_token_credential_hooks


Flask OAuth 2 Server
--------------------

.. module:: authlib.flask.oauth2

.. autoclass:: AuthorizationServer
    :members:
        register_grant_endpoint,
        register_revoke_token_endpoint,
        create_expires_generator,
        create_bearer_token_generator,
        validate_authorization_request,
        create_authorization_response,
        create_token_response,
        create_revocation_response

.. autoclass:: ResourceProtector
    :member-order: bysource
    :members:

.. data:: current_token

    Routes protected by :class:`ResourceProtector` can access current token
    with this variable.

Cache Helper Functions
~~~~~~~~~~~~~~~~~~~~~~

.. module:: authlib.flask.oauth2.cache

.. autofunction:: register_cache_authorization_code


SQLAlchemy Helper Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: authlib.flask.oauth2.sqla

.. autofunction:: create_query_client_func
