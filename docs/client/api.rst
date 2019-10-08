Client API References
=====================

.. meta::
   :description: API references on Authlib Client and its related Flask/Django integrations.

This part of the documentation covers the interface of Authlib Client.

Requests OAuth Sessions
-----------------------

.. module:: authlib.integrations.requests_client

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

.. autoclass:: OAuth2Auth
    :members:

.. autoclass:: AssertionSession
    :members:
    :member-order: bysource


httpx OAuth Clients
-------------------

.. module:: authlib.integrations.httpx_client

.. autoclass:: OAuth1Client
    :members:
        create_authorization_url,
        fetch_request_token,
        fetch_access_token,
        parse_authorization_response

.. autoclass:: OAuth1Auth
    :members:


.. autoclass:: AsyncOAuth1Client
    :members:
        create_authorization_url,
        fetch_request_token,
        fetch_access_token,
        parse_authorization_response


.. autoclass:: OAuth2Client
    :members:
        register_client_auth_method,
        create_authorization_url,
        fetch_token,
        fetch_access_token,
        refresh_token,
        revoke_token,
        register_compliance_hook


.. autoclass:: OAuth2Auth
    :members:


Flask Registry and RemoteApp
----------------------------

.. module:: authlib.integrations.flask_client

.. autoclass:: OAuth
    :members:
        init_app,
        register,
        create_client

.. autoclass:: RemoteApp
    :members:
        authorize_redirect,
        authorize_access_token,
        save_authorize_data,
        save_authorize_state,
        get,
        post,
        patch,
        put,
        delete

Django Registry and RemoteApp
-----------------------------

.. module:: authlib.integrations.django_client

.. autoclass:: OAuth
    :members:
        register,
        create_client

.. autoclass:: RemoteApp
    :members:
        authorize_redirect,
        authorize_access_token,
        save_authorize_data,
        get,
        post,
        patch,
        put,
        delete

Starlette Registry and RemoteApp
--------------------------------

.. module:: authlib.integrations.starlette_client

.. autoclass:: OAuth
    :members:
        register,
        create_client

.. autoclass:: RemoteApp
    :members:
        authorize_redirect,
        authorize_access_token,
        save_authorize_data,
        get,
        post,
        patch,
        put,
        delete
