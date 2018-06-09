from authlib.specs.rfc5849 import errors
from .oauth1_server import TestCase


class DjangoOAuthTest(TestCase):
    def test_invalid_authorization(self):
        url = '/oauth/authorize'
        request = self.factory.post(url)
        self.assertRaises(
            errors.MissingRequiredParameterError,
            self.server.check_authorization_request,
            request
        )

        request = self.factory.post(url, data={'oauth_token': 'a'})
        self.assertRaises(
            errors.InvalidTokenError,
            self.server.check_authorization_request,
            request
        )

    def test_authorize_denied(self):
        initiate_url = '/oauth/initiate'
        authorize_url = '/oauth/authorize'

        request = self.factory.post(initiate_url, data={
            'oauth_consumer_key': 'client',
            'oauth_callback': 'oob',
            'oauth_signature_method': 'PLAINTEXT',
            'oauth_signature': 'secret&'
        })
        resp = self.server.create_temporary_credentials_response(request)
        self.assertIn('oauth_token', resp)
