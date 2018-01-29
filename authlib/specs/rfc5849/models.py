
class ClientMixin(object):
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

    def get_client_secret(self):
        """A method to return the client_secret of this client. For instance,
        the database table has a column called ``client_secret``::

            def get_client_secret(self):
                return self.client_secret
        """
        raise NotImplementedError()

    def get_rsa_public_key(self):
        """A method to get the RSA public key for RSA-SHA1 signature method.
        For instance, the value is saved on column ``rsa_public_key``::

            def get_rsa_public_key(self):
                return self.rsa_public_key
        """
        raise NotImplementedError()


class CredentialMixin(object):
    def get_oauth_token(self):
        """A method to get the value of ``oauth_token``. For instance, the
        database table has a column called ``oauth_token``::

            def get_oauth_token(self):
                return self.oauth_token

        :return: A string
        """
        raise NotImplementedError()

    def get_oauth_token_secret(self):
        """A method to get the value of ``oauth_token_secret``. For instance,
        the database table has a column called ``oauth_token_secret``::

            def get_oauth_token_secret(self):
                return self.oauth_token_secret

        :return: A string
        """
        raise NotImplementedError()


class TemporaryCredentialMixin(CredentialMixin):
    def get_client_id(self):
        """A method to get the client_id associated with this credential.
        For instance, the table in the database has a column ``client_id``::

            def get_client_id(self):
                return self.client_id
        """
        raise NotImplementedError()

    def get_redirect_uri(self):
        """A method to get temporary credential's ``oauth_callback``.
        For instance, the database table for temporary credential has a
        column called ``oauth_callback``::

            def get_redirect_uri(self):
                return self.oauth_callback

        :return: A URL string
        """
        raise NotImplementedError()

    def get_grant_user(self):
        """A method to get the grant user information of this temporary
        credential. For instance, grant user is stored in database on
        ``user_id`` column::

            def get_grant_user(self):
                return self.user_id

        :return: grant user ID
        """
        raise NotImplementedError()

    def check_verifier(self, verifier):
        """A method to check if the given verifier matches this temporary
        credential. For instance that this temporary credential has recorded
        the value in database as column ``oauth_verifier``::

            def check_verifier(self, verifier):
                return self.oauth_verifier == verifier

        :return: Boolean
        """
        raise NotImplementedError()


class TokenCredentialMixin(CredentialMixin):
    def set_grant_user(self, grant_user):
        """A method to save ``grant_user`` information into token credential.
        A ``grant_user`` is usually a string/int of the user's ID::

            def set_grant_user(self, grant_user):
                self.user_id = grant_user
        """
        raise NotImplementedError()
