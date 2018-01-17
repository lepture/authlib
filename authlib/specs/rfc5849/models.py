
class ClientMixin(object):
    # client_id - oauth_consumer_key
    # client_secret - oauth_consumer_secret
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
        raise NotImplementedError()


class TemporaryCredentialMixin(object):
    # client_id
    # oauth_token
    # oauth_token_secret
    # oauth_callback
    # oauth_verifier

    def get_redirect_uri(self):
        return self.oauth_callback
