from authlib.oauth2.rfc6749 import grants, errors
from .models import User, Client
from .models import CodeGrantMixin, generate_authorization_code
from .oauth2_server import TestCase


class AuthorizationCodeGrant(CodeGrantMixin, grants.AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, request):
        return generate_authorization_code(client, grant_user, request)



class AuthorizationCodeTest(TestCase):
    def create_server(self):
        server = super(AuthorizationCodeTest, self).create_server()
        server.register_grant(AuthorizationCodeGrant)
        return server

    def prepare_data(self, response_type='code', scope=''):
        user = User(username='foo')
        user.save()
        client = Client(
            user_id=user.pk,
            client_id='client',
            client_secret='secret',
            response_type=response_type,
            scope=scope,
            default_redirect_uri='https://a.b',
        )
        client.save()

    def test_validate_consent_request_client(self):
        server = self.create_server()
        url = '/authorize?response_type=code'
        request = self.factory.get(url)
        self.assertRaises(
            errors.InvalidClientError,
            server.validate_consent_request,
            request
        )

        url = '/authorize?response_type=code&client_id=client'
        request = self.factory.get(url)
        self.assertRaises(
            errors.InvalidClientError,
            server.validate_consent_request,
            request
        )

        self.prepare_data(response_type='')
        self.assertRaises(
            errors.UnauthorizedClientError,
            server.validate_consent_request,
            request
        )

    def test_validate_consent_request_redirect_uri(self):
        server = self.create_server()
        self.prepare_data()

        base_url = '/authorize?response_type=code&client_id=client'
        url = base_url + '&redirect_uri=https%3A%2F%2Fa.c'
        request = self.factory.get(url)
        self.assertRaises(
            errors.InvalidRequestError,
            server.validate_consent_request,
            request
        )

        url = base_url + '&redirect_uri=https%3A%2F%2Fa.b'
        request = self.factory.get(url)
        grant = server.validate_consent_request(request)
        self.assertIsInstance(grant, AuthorizationCodeGrant)
