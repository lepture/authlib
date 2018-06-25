class JWSAlgorithm(object):
    """Interface for JWS algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWS with this base implementation.
    """
    def prepare_private_key(self, key):
        """Prepare key for sign signature."""
        raise NotImplementedError

    def prepare_public_key(self, key):
        """Prepare key for verify signature."""
        raise NotImplementedError

    def sign(self, msg, key):
        """Sign the text msg with a private/sign key.

        :param msg: message bytes to be signed
        :param key: private key to sign the message
        :return: bytes
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """Verify the signature of text msg with a public/verify key.

        :param msg: message bytes to be signed
        :param key: public key to verify the signature
        :param sig: result signature to be compared
        :return: boolean
        """
        raise NotImplementedError


class JWSHeader(dict):
    def __init__(self, protected, header):
        obj = {}
        if protected:
            obj.update(protected)
        if header:
            obj.update(header)
        super(JWSHeader, self).__init__(obj)
        self.protected = protected
        self.header = header

    @classmethod
    def from_dict(cls, obj):
        if isinstance(obj, cls):
            return obj
        return cls(obj.get('protected'), obj.get('header'))
