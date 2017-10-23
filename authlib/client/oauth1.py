from requests import Session


class OAuth1Session(Session):
    def __init__(self, client_key, client_secret=None, token=None,
                 callback_uri=None, rsa_key=None, verifier=None):
        super(OAuth1Session, self).__init__()

        self.client_key = client_key
        self.client_secret = client_secret
        self.token = token
        self.callback_uri = callback_uri
        self.rsa_key = rsa_key
        self.verifier = verifier

    def authorization_url(self, url, request_token=None, **kwargs):
        pass

    def fetch_request_token(self, url, realm=None, **kwargs):
        return {}

    def fetch_access_token(self, url, verifier=None, **kwargs):
        pass

    def parse_authorization_response(self, url):
        pass
