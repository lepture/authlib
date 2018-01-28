from .oauth1_server import (
    TestCase,
    create_authorization_server,
    decode_response
)


class AuthorizationTest(TestCase):
    def test_fetch_temporary_credential(self):
        create_authorization_server(self.app, True)

        url = '/oauth/initiate'
        rv = self.client.post(url)
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
