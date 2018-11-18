API References of Flask OAuth 2.0 Server
========================================

This part of the documentation covers the interface of Flask OAuth 2.0
Server.

.. module:: authlib.flask.oauth2

.. autoclass:: AuthorizationServer
    :members:
        register_grant,
        register_endpoint,
        create_token_expires_in_generator,
        create_bearer_token_generator,
        validate_consent_request,
        create_authorization_response,
        create_token_response,
        create_endpoint_response

.. autoclass:: ResourceProtector
    :member-order: bysource
    :members:

.. data:: current_token

    Routes protected by :class:`ResourceProtector` can access current token
    with this variable::

        from authlib.flask.oauth2 import current_token

        @require_oauth()
        @app.route('/user_id')
        def user_id():
            # current token instance of the OAuth Token model
            return current_token.user_id

Cache Helper Functions
----------------------

.. module:: authlib.flask.oauth2.cache

.. autofunction:: register_cache_authorization_code


SQLAlchemy Helper Functions
---------------------------

.. module:: authlib.flask.oauth2.sqla

.. autofunction:: create_query_client_func

.. autofunction:: create_save_token_func

.. autofunction:: create_query_token_func

.. autofunction:: create_revocation_endpoint

.. autofunction:: create_bearer_token_validator
