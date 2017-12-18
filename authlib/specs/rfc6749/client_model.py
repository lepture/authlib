
class ClientMixin(object):
    """Implementation of OAuth 2 Client described in `Section 2`_ with
    some methods to help validation. A client has at least these information:

    * client_type: Determine if a client is confidential or public.
    * client_id: A string represents client identifier.
    * client_secret: A string represents client password.

    .. _`Section 2`: https://tools.ietf.org/html/rfc6749#section-2
    """

    @classmethod
    def get_by_client_id(cls, client_id):
        """A class method to query client information by client_id. Developers
        should implement it in subclass::

            @classmethod
            def get_by_client_id(cls, client_id):
                return cls.query.get(client_id)

        :param client_id: A client identifier string.
        :return: client
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

    def check_client_type(self, client_type):
        """OAuth defines two client types, based on their ability to
        authenticate securely with the authorization server.

        confidential
            Clients capable of maintaining the confidentiality of their
            credentials (e.g., client implemented on a secure server with
            restricted access to the client credentials), or capable of secure
            client authentication using other means.

        public
            Clients incapable of maintaining the confidentiality of their
            credentials (e.g., clients executing on the device used by the
            resource owner, such as an installed native application or a web
            browser-based application), and incapable of secure client
            authentication via any other means.

        :param client_type: the required client_type, confidential or public
        :return: bool
        """
        raise NotImplementedError()

    def check_response_type(self, response_type):
        """Validate if the client can handle the given response_type. There
        are two response types defined by RFC6749: code and token. For
        instance, there is a ``allowed_response_types`` column in your client::

            def check_response_type(response_type):
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

            def check_grant_type(grant_type):
                return grant_type in self.grant_types

        :param grant_type: the requested grant_type string.
        :return: bool
        """
        raise NotImplementedError()

    def check_requested_scopes(self, scopes):
        """Validate if the request scopes are supported by this client. It can
        always be ``True``. For instance, there is a ``allowed_scopes`` column::

            def check_requested_scopes(self, scopes):
                return self.allowed_scopes.issuperset(scopes)

        :param scopes: the requested scopes set.
        :return: bool
        """
        raise NotImplementedError()
