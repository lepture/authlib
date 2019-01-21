Client API References
=====================

.. meta::
   :description: API references on Authlib Client and its related Flask/Django integrations.

This part of the documentation covers the interface of Authlib Client.

Sessions and Client
-------------------

.. module:: authlib.client

.. autoclass:: OAuth1Session
    :members:
        create_authorization_url,
        fetch_request_token,
        fetch_access_token,
        parse_authorization_response

.. autoclass:: OAuth1Auth
    :members:

.. autoclass:: OAuth2Session
    :members:
        register_client_auth_method,
        create_authorization_url,
        fetch_token,
        fetch_access_token,
        refresh_token,
        revoke_token,
        register_compliance_hook

.. autoclass:: AssertionSession
    :members:
    :member-order: bysource

.. autoclass:: OAuth2Auth
    :members:

.. autoclass:: OAuthClient
    :members:
    :member-order: bysource


Flask Registry and RemoteApp
----------------------------

.. module:: authlib.flask.client

.. autoclass:: OAuth
    :members:

.. autoclass:: RemoteApp
    :members:


Django Registry and RemoteApp
-----------------------------

.. module:: authlib.django.client

.. autoclass:: OAuth
    :members:

.. autoclass:: RemoteApp
    :members:
