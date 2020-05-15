import mock
import time
import pytest
from copy import deepcopy
from authlib.common.security import generate_token
from authlib.common.urls import url_encode
from authlib.integrations.httpx_client import (
    OAuthError,
    AsyncOAuth2Client,
)
from tests.py3.utils import MockDispatch


default_token = {
    'token_type': 'Bearer',
    'access_token': 'a',
    'refresh_token': 'b',
    'expires_in': '3600',
    'expires_at': int(time.time()) + 3600,
}


@pytest.mark.asyncio
async def test_add_token_to_header():
    async def assert_func(request):
        token = 'Bearer ' + default_token['access_token']
        auth_header = request.headers.get('authorization')
        assert auth_header == token

    mock_response = MockDispatch({'a': 'a'}, assert_func=assert_func)
    async with AsyncOAuth2Client(
            'foo',
            token=default_token,
            app=mock_response
    ) as client:
        resp = await client.get('https://i.b')

    data = resp.json()
    assert data['a'] == 'a'


@pytest.mark.asyncio
async def test_add_token_to_body():
    async def assert_func(request):
        content = await request.body()
        assert default_token['access_token'] in content.decode()

    mock_response = MockDispatch({'a': 'a'}, assert_func=assert_func)
    async with AsyncOAuth2Client(
            'foo',
            token=default_token,
            token_placement='body',
            app=mock_response
    ) as client:
        resp = await client.get('https://i.b')

    data = resp.json()
    assert data['a'] == 'a'


@pytest.mark.asyncio
async def test_add_token_to_uri():
    async def assert_func(request):
        assert default_token['access_token'] in str(request.url)

    mock_response = MockDispatch({'a': 'a'}, assert_func=assert_func)
    async with AsyncOAuth2Client(
            'foo',
            token=default_token,
            token_placement='uri',
            app=mock_response
    ) as client:
        resp = await client.get('https://i.b')

    data = resp.json()
    assert data['a'] == 'a'


def test_create_authorization_url():
    url = 'https://example.com/authorize?foo=bar'

    sess = AsyncOAuth2Client(client_id='foo')
    auth_url, state = sess.create_authorization_url(url)
    assert state in auth_url
    assert 'client_id=foo' in auth_url
    assert 'response_type=code' in auth_url

    sess = AsyncOAuth2Client(client_id='foo', prompt='none')
    auth_url, state = sess.create_authorization_url(
        url, state='foo', redirect_uri='https://i.b', scope='profile')
    assert state == 'foo'
    assert 'i.b' in auth_url
    assert 'profile' in auth_url
    assert 'prompt=none' in auth_url


def test_code_challenge():
    sess = AsyncOAuth2Client('foo', code_challenge_method='S256')

    url = 'https://example.com/authorize'
    auth_url, _ = sess.create_authorization_url(
        url, code_verifier=generate_token(48))
    assert 'code_challenge=' in auth_url
    assert 'code_challenge_method=S256' in auth_url


def test_token_from_fragment():
    sess = AsyncOAuth2Client('foo')
    response_url = 'https://i.b/callback#' + url_encode(default_token.items())
    assert sess.token_from_fragment(response_url) == default_token
    token = sess.fetch_token(authorization_response=response_url)
    assert token == default_token


@pytest.mark.asyncio
async def test_fetch_token_post():
    url = 'https://example.com/token'

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert 'code=v' in content
        assert 'client_id=' in content
        assert 'grant_type=authorization_code' in content

    mock_response = MockDispatch(default_token, assert_func=assert_func)
    async with AsyncOAuth2Client('foo', app=mock_response) as client:
        token = await client.fetch_token(url, authorization_response='https://i.b/?code=v')
        assert token == default_token

    async with AsyncOAuth2Client(
            'foo',
            token_endpoint_auth_method='none',
            app=mock_response
    ) as client:
        token = await client.fetch_token(url, code='v')
        assert token == default_token

    mock_response = MockDispatch({'error': 'invalid_request'})
    async with AsyncOAuth2Client('foo', app=mock_response) as client:
        with pytest.raises(OAuthError):
            await client.fetch_token(url)


@pytest.mark.asyncio
async def test_fetch_token_get():
    url = 'https://example.com/token'

    async def assert_func(request):
        url = str(request.url)
        assert 'code=v' in url
        assert 'client_id=' in url
        assert 'grant_type=authorization_code' in url

    mock_response = MockDispatch(default_token, assert_func=assert_func)
    async with AsyncOAuth2Client('foo', app=mock_response) as client:
        authorization_response = 'https://i.b/?code=v'
        token = await client.fetch_token(
            url, authorization_response=authorization_response, method='GET')
        assert token == default_token

    async with AsyncOAuth2Client(
            'foo',
            token_endpoint_auth_method='none',
            app=mock_response
    ) as client:
        token = await client.fetch_token(url, code='v', method='GET')
        assert token == default_token

        token = await client.fetch_token(url + '?q=a', code='v', method='GET')
        assert token == default_token


@pytest.mark.asyncio
async def test_token_auth_method_client_secret_post():
    url = 'https://example.com/token'

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert 'code=v' in content
        assert 'client_id=' in content
        assert 'client_secret=bar' in content
        assert 'grant_type=authorization_code' in content

    mock_response = MockDispatch(default_token, assert_func=assert_func)
    async with AsyncOAuth2Client(
            'foo', 'bar',
            token_endpoint_auth_method='client_secret_post',
            app=mock_response
    ) as client:
        token = await client.fetch_token(url, code='v')

    assert token == default_token


@pytest.mark.asyncio
async def test_access_token_response_hook():
    url = 'https://example.com/token'

    def _access_token_response_hook(resp):
        assert resp.json() == default_token
        return resp

    access_token_response_hook = mock.Mock(side_effect=_access_token_response_hook)
    app = MockDispatch(default_token)
    async with AsyncOAuth2Client('foo', token=default_token, app=app) as sess:
        sess.register_compliance_hook(
            'access_token_response',
            access_token_response_hook
        )
        assert await sess.fetch_token(url) == default_token
        assert access_token_response_hook.called is True


@pytest.mark.asyncio
async def test_password_grant_type():
    url = 'https://example.com/token'

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert 'username=v' in content
        assert 'scope=profile' in content
        assert 'grant_type=password' in content

    app = MockDispatch(default_token, assert_func=assert_func)
    async with AsyncOAuth2Client('foo', scope='profile', app=app) as sess:
        token = await sess.fetch_token(url, username='v', password='v')
        assert token == default_token

        token = await sess.fetch_token(
            url, username='v', password='v', grant_type='password')
        assert token == default_token


@pytest.mark.asyncio
async def test_client_credentials_type():
    url = 'https://example.com/token'

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert 'scope=profile' in content
        assert 'grant_type=client_credentials' in content

    app = MockDispatch(default_token, assert_func=assert_func)
    async with AsyncOAuth2Client('foo', scope='profile', app=app) as sess:
        token = await sess.fetch_token(url)
        assert token == default_token

        token = await sess.fetch_token(url, grant_type='client_credentials')
        assert token == default_token


@pytest.mark.asyncio
async def test_cleans_previous_token_before_fetching_new_one():
    now = int(time.time())
    new_token = deepcopy(default_token)
    past = now - 7200
    default_token['expires_at'] = past
    new_token['expires_at'] = now + 3600
    url = 'https://example.com/token'

    app = MockDispatch(new_token)
    with mock.patch('time.time', lambda: now):
        async with AsyncOAuth2Client('foo', token=default_token, app=app) as sess:
            assert await sess.fetch_token(url) == new_token


def test_token_status():
    token = dict(access_token='a', token_type='bearer', expires_at=100)
    sess = AsyncOAuth2Client('foo', token=token)
    assert sess.token.is_expired() is True


@pytest.mark.asyncio
async def test_auto_refresh_token():

    async def _update_token(token, refresh_token=None, access_token=None):
        assert refresh_token == 'b'
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(
        access_token='a', refresh_token='b',
        token_type='bearer', expires_at=100
    )

    app = MockDispatch(default_token)
    async with AsyncOAuth2Client(
            'foo', token=old_token, token_endpoint='https://i.b/token',
            update_token=update_token, app=app
    ) as sess:
        await sess.get('https://i.b/user')
        assert update_token.called is True

    old_token = dict(
        access_token='a',
        token_type='bearer',
        expires_at=100
    )
    async with AsyncOAuth2Client(
            'foo', token=old_token, token_endpoint='https://i.b/token',
            update_token=update_token, app=app
    ) as sess:
        with pytest.raises(OAuthError):
            await sess.get('https://i.b/user')


@pytest.mark.asyncio
async def test_auto_refresh_token2():

    async def _update_token(token, refresh_token=None, access_token=None):
        assert access_token == 'a'
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(
        access_token='a',
        token_type='bearer',
        expires_at=100
    )

    app = MockDispatch(default_token)

    async with AsyncOAuth2Client(
            'foo', token=old_token,
            token_endpoint='https://i.b/token',
            grant_type='client_credentials',
            app=app,
    ) as client:
        await client.get('https://i.b/user')
        assert update_token.called is False

    async with AsyncOAuth2Client(
            'foo', token=old_token, token_endpoint='https://i.b/token',
            update_token=update_token, grant_type='client_credentials',
            app=app,
    ) as client:
        await client.get('https://i.b/user')
        assert update_token.called is True


@pytest.mark.asyncio
async def test_auto_refresh_token3():
    async def _update_token(token, refresh_token=None, access_token=None):
        assert access_token == 'a'
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(
        access_token='a',
        token_type='bearer',
        expires_at=100
    )

    app = MockDispatch(default_token)

    async with AsyncOAuth2Client(
            'foo', token=old_token, token_endpoint='https://i.b/token',
            update_token=update_token, grant_type='client_credentials',
            app=app,
    ) as client:
        await client.post('https://i.b/user', json={'foo': 'bar'})
        assert update_token.called is True


@pytest.mark.asyncio
async def test_revoke_token():
    answer = {'status': 'ok'}
    app = MockDispatch(answer)

    async with AsyncOAuth2Client('a', app=app) as sess:
        resp = await sess.revoke_token('https://i.b/token', 'hi')
        assert resp.json() == answer

        resp = await sess.revoke_token(
            'https://i.b/token', 'hi',
            token_type_hint='access_token'
        )
        assert resp.json() == answer


@pytest.mark.asyncio
async def test_request_without_token():
    async with AsyncOAuth2Client('a') as client:
        with pytest.raises(OAuthError):
            await client.get('https://i.b/token')
