import time
import pytest
from authlib.integrations.httpx_client import AssertionClient
from ..wsgi_helper import MockDispatch


default_token = {
    'token_type': 'Bearer',
    'access_token': 'a',
    'refresh_token': 'b',
    'expires_in': '3600',
    'expires_at': int(time.time()) + 3600,
}


def test_refresh_token():
    def verifier(request):
        content = request.form
        if str(request.url) == 'https://i.b/token':
            assert 'assertion' in content

    with AssertionClient(
        'https://i.b/token',
        issuer='foo',
        subject='foo',
        audience='foo',
        alg='HS256',
        key='secret',
        app=MockDispatch(default_token, assert_func=verifier)
    ) as client:
        client.get('https://i.b')

    # trigger more case
    now = int(time.time())
    with AssertionClient(
        'https://i.b/token',
        issuer='foo',
        subject=None,
        audience='foo',
        issued_at=now,
        expires_at=now + 3600,
        header={'alg': 'HS256'},
        key='secret',
        scope='email',
        client_id='client',
        claims={'test_mode': 'true'},
        app=MockDispatch(default_token, assert_func=verifier)
    ) as client:
        client.get('https://i.b')
        client.get('https://i.b')


def test_without_alg():
    with AssertionClient(
        'https://i.b/token',
        issuer='foo',
        subject='foo',
        audience='foo',
        key='secret',
        app=MockDispatch(default_token)
    ) as client:
        with pytest.raises(ValueError):
            client.get('https://i.b')
