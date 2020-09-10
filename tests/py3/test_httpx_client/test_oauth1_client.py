import pytest
from authlib.integrations.httpx_client import (
    OAuthError,
    OAuth1Client,
    SIGNATURE_TYPE_BODY,
    SIGNATURE_TYPE_QUERY,
)
from tests.py3.utils import MockDispatch

oauth_url = 'https://example.com/oauth'


@pytest.mark.asyncio
def test_fetch_request_token_via_header():
    request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

    def assert_func(request):
        auth_header = request.headers.get('authorization')
        assert 'oauth_consumer_key="id"' in auth_header
        assert 'oauth_signature=' in auth_header

    app = MockDispatch(request_token, assert_func=assert_func)
    with OAuth1Client('id', 'secret', app=app) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


@pytest.mark.asyncio
def test_fetch_request_token_via_body():
    request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

    def assert_func(request):
        auth_header = request.headers.get('authorization')
        assert auth_header is None

        content = request.form
        assert content.get('oauth_consumer_key') == 'id'
        assert 'oauth_signature' in content

    mock_response = MockDispatch(request_token, assert_func=assert_func)

    with OAuth1Client(
        'id', 'secret', signature_type=SIGNATURE_TYPE_BODY,
        app=mock_response,
    ) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


@pytest.mark.asyncio
def test_fetch_request_token_via_query():
    request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

    def assert_func(request):
        auth_header = request.headers.get('authorization')
        assert auth_header is None

        url = str(request.url)
        assert 'oauth_consumer_key=id' in url
        assert '&oauth_signature=' in url

    mock_response = MockDispatch(request_token, assert_func=assert_func)

    with OAuth1Client(
        'id', 'secret', signature_type=SIGNATURE_TYPE_QUERY,
        app=mock_response,
    ) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


@pytest.mark.asyncio
def test_fetch_access_token():
    request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

    def assert_func(request):
        auth_header = request.headers.get('authorization')
        assert 'oauth_verifier="d"' in auth_header
        assert 'oauth_token="foo"' in auth_header
        assert 'oauth_consumer_key="id"' in auth_header
        assert 'oauth_signature=' in auth_header

    mock_response = MockDispatch(request_token, assert_func=assert_func)
    with OAuth1Client(
        'id', 'secret', token='foo', token_secret='bar',
        app=mock_response,
    ) as client:
        with pytest.raises(OAuthError):
            client.fetch_access_token(oauth_url)

        response = client.fetch_access_token(oauth_url, verifier='d')

    assert response == request_token


@pytest.mark.asyncio
def test_get_via_header():
    mock_response = MockDispatch(b'hello')
    with OAuth1Client(
        'id', 'secret', token='foo', token_secret='bar',
        app=mock_response,
    ) as client:
        response = client.get('https://example.com/')

    assert response.content == b'hello'
    request = response.request
    auth_header = request.headers.get('authorization')
    assert 'oauth_token="foo"' in auth_header
    assert 'oauth_consumer_key="id"' in auth_header
    assert 'oauth_signature=' in auth_header


@pytest.mark.asyncio
def test_get_via_body():
    def assert_func(request):
        content = request.form
        assert content.get('oauth_token') == 'foo'
        assert content.get('oauth_consumer_key') == 'id'
        assert 'oauth_signature' in content

    mock_response = MockDispatch(b'hello', assert_func=assert_func)
    with OAuth1Client(
        'id', 'secret', token='foo', token_secret='bar',
        signature_type=SIGNATURE_TYPE_BODY,
        app=mock_response,
    ) as client:
        response = client.post('https://example.com/')

    assert response.content == b'hello'

    request = response.request
    auth_header = request.headers.get('authorization')
    assert auth_header is None


@pytest.mark.asyncio
def test_get_via_query():
    mock_response = MockDispatch(b'hello')
    with OAuth1Client(
        'id', 'secret', token='foo', token_secret='bar',
        signature_type=SIGNATURE_TYPE_QUERY,
        app=mock_response,
    ) as client:
        response = client.get('https://example.com/')

    assert response.content == b'hello'
    request = response.request
    auth_header = request.headers.get('authorization')
    assert auth_header is None

    url = str(request.url)
    assert 'oauth_token=foo' in url
    assert 'oauth_consumer_key=id' in url
    assert 'oauth_signature=' in url
