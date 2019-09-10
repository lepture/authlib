"""
    authlib.oauth2.rfc6749.models
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module defines how to construct Client, AuthorizationCode and Token.
"""


class ClientMixin(object):
    """Implementation of OAuth 2 Client described in `Section 2`_ with
    some methods to help validation. A client has at least these information:

    * client_id: A string represents client identifier.
    * client_secret: A string represents client password.
    * token_endpoint_auth_method: A way to authenticate client at token
                                  endpoint.

    .. _`Section 2`: https://tools.ietf.org/html/rfc6749#section-2
    """

    def get_client_id(self):
        """A method to return client_id of the client. For instance, the value
        in database is saved in a column called ``client_id``::

            def get_client_id(self):
                return self.client_id

        :return: string
        """
        raise NotImplementedError()

    def get_default_redirect_uri(self):
        """A method to get client default redirect_uri. For instance, the
        database table for client has a column called ``default_redirect_uri``::

            def get_default_redirect_uri(self):
                return self.default_redirect_uri

        :return: A URL string
        """
        raise NotImplementedError()

    def get_allowed_scope(self, scope):
        """A method to return a list of requested scopes which are supported by
        this client. For instance, there is a ``scope`` column::

            def get_allowed_scope(self, scope):
                if not scope:
                    return ''
                allowed = set(scope_to_list(self.scope))
                return list_to_scope([s for s in scope.split() if s in allowed])

        :param scope: the requested scope.
        :return: string of scope
        """
        raise NotImplementedError()

    def check_redirect_uri(self, redirect_uri):
        """Validate redirect_uri parameter in Authorization Endpoints. For
        instance, in the client table, there is an ``allowed_redirect_uris``
        column::

            def check_redirect_uri(self, redirect_uri):
                return redirect_uri in self.allowed_redirect_uris

        :param redirect_uri: A URL string for redirecting.
        :return: bool
        """
        raise NotImplementedError()

    def has_client_secret(self):
        """A method returns that if the client has ``client_secret`` value.
        If the value is in ``client_secret`` column::

            def has_client_secret(self):
                return bool(self.client_secret)

        :return: bool
        """
        raise NotImplementedError()

    def check_client_secret(self, client_secret):
        """Check client_secret matching with the client. For instance, in
        the client table, the column is called ``client_secret``::

            def check_client_secret(self, client_secret):
                return self.client_secret == client_secret

        :param client_secret: A string of client secret
        :return: bool
        """
        raise NotImplementedError()

    def check_token_endpoint_auth_method(self, method):
        """Check client ``token_endpoint_auth_method`` defined via `RFC7591`_.
        Values defined by this specification are:

        *  "none": The client is a public client as defined in OAuth 2.0,
            and does not have a client secret.

        *  "client_secret_post": The client uses the HTTP POST parameters
            as defined in OAuth 2.0

        *  "client_secret_basic": The client uses HTTP Basic as defined in
            OAuth 2.0

        .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
        """
        raise NotImplementedError()

    def check_response_type(self, response_type):
        """Validate if the client can handle the given response_type. There
        are two response types defined by RFC6749: code and token. For
        instance, there is a ``allowed_response_types`` column in your client::

            def check_response_type(self, response_type):
                return response_type in self.response_types

        :param response_type: the requested response_type string.
        :return: bool
        """
        raise NotImplementedError()

    def check_grant_type(self, grant_type):
        """Validate if the client can handle the given grant_type. There are
        four grant types defined by RFC6749:

        * authorization_code
        * implicit
        * client_credentials
        * password

        For instance, there is a ``allowed_grant_types`` column in your client::

            def check_grant_type(self, grant_type):
                return grant_type in self.grant_types

        :param grant_type: the requested grant_type string.
        :return: bool
        """
        raise NotImplementedError()


class AuthorizationCodeMixin(object):
    def get_redirect_uri(self):
        """A method to get authorization code's ``redirect_uri``.
        For instance, the database table for authorization code has a
        column called ``redirect_uri``::

            def get_redirect_uri(self):
                return self.redirect_uri

        :return: A URL string
        """
        raise NotImplementedError()

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::

            def get_scope(self):
                return self.scope

        :return: scope string
        """
        raise NotImplementedError()


class TokenMixin(object):
    def get_client_id(self):
        """A method to return client_id of the token. For instance, the value
        in database is saved in a column called ``client_id``::

            def get_client_id(self):
                return self.client_id

        :return: string
        """
        raise NotImplementedError()

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::

            def get_scope(self):
                return self.scope

        :return: scope string
        """
        raise NotImplementedError()

    def get_expires_in(self):
        """A method to get the ``expires_in`` value of the token. e.g.
        the column is called ``expires_in``::

            def get_expires_in(self):
                return self.expires_in

        :return: timestamp int
        """
        raise NotImplementedError()

    def get_expires_at(self):
        """A method to get the value when this token will be expired. e.g.
        it would be::

            def get_expires_at(self):
                return self.created_at + self.expires_in

        :return: timestamp int
        """
        raise NotImplementedError()
