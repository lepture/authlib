Server Reference
================

.. meta::
   :description: API references on Authlib server part, including Flask related integrations.

This part of the documentation covers the interface of Authlib Server.

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


.. autoclass:: BearerTokenValidator
   :member-order: bysource
   :members:

.. data:: current_token

   Routes protected by :class:`ResourceProtector` can access current token
   with this variable.
