
class ClientMetadataClaims(dict):
    # https://tools.ietf.org/html/rfc7591#section-2
    REGISTERED_CLAIMS = [
        'redirect_uris',
        'token_endpoint_auth_method',
        'grant_types',
        'response_types',
        'client_name',
        'client_uri',
        'logo_uri',
        'scope',
        'contacts',
        'tos_uri',
        'policy_uri',
        'jwks_uri',
        'jwks',
        'software_id',
        'software_version',
    ]

    def __init__(self, payload, header, options=None, params=None):
        super(ClientMetadataClaims, self).__init__(payload)
        self.header = header
        self.options = options or {}
        self.params = params or {}

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTERED_CLAIMS:
                return self.get(key)
            raise error

    def validate_redirect_uris(self):
        pass

    def validate_token_endpoint_auth_method(self):
        # If unspecified or omitted, the default is "client_secret_basic"
        pass

    def validate_grant_types(self):
        pass

    def validate(self):
        pass
