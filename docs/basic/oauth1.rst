.. meta::
    :description: Understand the concepts in OAuth 1.0, the authorization flow,
        roles, signatures and etc.
    :image: https://user-images.githubusercontent.com/290496/48671968-2c316080-eb73-11e8-9e6a-9e895cd67262.png

.. _understand_oauth1:

Understand OAuth 1.0
====================

    OAuth provides a method for clients to access server resources on
    behalf of a resource owner (such as a different client or an end-
    user).  It also provides a process for end-users to authorize third-
    party access to their server resources without sharing their
    credentials (typically, a username and password pair), using user-
    agent redirections.

This section will help developers understand the concepts in OAuth 1.0, but not
in deep. Here is an overview of a typical OAuth 1.0 flow:

.. figure:: https://user-images.githubusercontent.com/290496/48671968-2c316080-eb73-11e8-9e6a-9e895cd67262.png
    :alt: OAuth 1.0 Flow

It takes more steps to obtain an access token than :ref:`OAuth 2.0 <understand_oauth2>`.

Roles in OAuth 1.0
------------------

There are usually three roles in an OAuth 1.0 flow. Let's take Twitter as an example,
you are building a mobile app to send tweets:

- **Client**: a client is a third-party application. In this case,
  it is your application.
- **Resource Owner**: the users on Twitter are the resource owners, since
  they own their tweets (resources).
- **Server**: authorization and resource server. In this case, it is twitter.

Credentials
-----------

During the OAuth 1.0 process, there are several credentials passed from server to client, and vice versa.

1. client credentials
2. temporary credentials
3. token credentials

OAuth 1.0 Flow
--------------

Let's take your mobile Twitter app as an example. When a user wants to send a tweet
through your application, he/she needs to authenticate at first. When the app is
opened, and the login button is clicked:

1. **Client** uses its **client credentials** to make a request to server, asking
   the server for a temporary credential.
2. **Server** responds with a **temporary credential** if it verified your client
   credential.
3. **Client** saves temporary credential for later use, then open a view for
   **resource owner** to grant the access.
4. When access is granted, **Server** responds with a **verifier** to client.
5. **Client** uses this **verifier and temporary credential** to make a request to
   the server asking for **token credentials**.
6. **Server** responds with access token if it verified everything.

And then **Client** can send tweets with the **token credentials**.

Signature
---------

In OAuth 1.0, every request **client** sending to **server** requires a signature.
The signature is calculated from:

1. credentials (client, temporary, token)
2. timestamp & nonce
3. other HTTP information
