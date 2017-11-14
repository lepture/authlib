Client Reference
================

This part of the documentation covers the interface of Authlib Client.

Sessions and Client
-------------------

.. module:: authlib.client

.. autoclass:: OAuth1Session
   :members:

.. autoclass:: OAuth2Session
   :members:

.. autoclass:: OAuthClient
   :members:


Flask Registry and RemoteApp
----------------------------

.. module:: authlib.client.flask

.. autoclass:: OAuth
   :members:

.. autoclass:: RemoteApp
   :members: authorize_access_token

   .. method:: authorize_redirect(callback_uri=None, **kwargs)

      Redirect to authorization server.


Django Registry and RemoteApp
-----------------------------

(Under construction)
