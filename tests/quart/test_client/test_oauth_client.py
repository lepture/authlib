import pytest
from quart import Quart, session
from authlib.common.urls import urlparse, url_decode
from authlib.integrations.quart_client import OAuth, OAuthError
from tests.client_base import get_bearer_token
from ...starlette.utils import AsyncPathMapDispatch


def test_register_remote_app():
    app = Quart(__name__)
    oauth = OAuth()
    oauth.init_app(app)
    with pytest.raises(AttributeError):
        assert oauth.dev.name == 'dev'

    oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
    )
    assert oauth.dev.name == 'dev'
    assert oauth.dev.client_id == 'dev'


@pytest.mark.asyncio
async def test_oauth1_authorize():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)

    app = AsyncPathMapDispatch({
        '/request-token': {'body': 'oauth_token=foo&oauth_verifier=baz'},
        '/token': {'body': 'oauth_token=a&oauth_token_secret=b'},
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        request_token_url='https://i.b/request-token',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        authorize_url='https://i.b/authorize',
        client_kwargs={
            'app': app,
        }
    )

    async with q_app.test_request_context("/"):
        resp = await client.authorize_redirect('https://b.com/bar')
        assert resp.status_code == 302
        url = resp.headers.get('Location')
        assert 'oauth_token=foo' in url
        state = session['_state_dev_foo']

    async with q_app.test_request_context('/?oauth_token=foo'):
        session['_state_dev_foo'] = state
        token = await client.authorize_access_token()
        assert token['oauth_token'] == 'a'


@pytest.mark.asyncio
async def test_oauth2_authorize():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    app = AsyncPathMapDispatch({
        '/token': {'body': get_bearer_token()}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        authorize_url='https://i.b/authorize',
        client_kwargs={
            'app': app,
        }
    )

    async with q_app.test_request_context("/"):
        resp = await client.authorize_redirect('https://b.com/bar')
        assert resp.status_code == 302
        url = resp.headers.get('Location')
        assert 'state=' in url
        state = dict(url_decode(urlparse.urlparse(url).query))['state']
        data = session[f'_state_dev_{state}']

    async with q_app.test_request_context(path=f'/?code=a&state={state}'):
        # session is cleared in tests
        session[f'_state_dev_{state}'] = data
        token = await client.authorize_access_token()
        assert token['access_token'] == 'a'



@pytest.mark.asyncio
async def test_oauth2_authorize_access_denied():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    app = AsyncPathMapDispatch({
        '/token': {'body': get_bearer_token()}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        authorize_url='https://i.b/authorize',
        client_kwargs={
            'app': app,
        }
    )

    async with q_app.test_request_context(path='/?error=access_denied&error_description=Not+Allowed'):
        with pytest.raises(OAuthError):
            await client.authorize_access_token()


@pytest.mark.asyncio
async def test_oauth2_authorize_code_challenge():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    app = AsyncPathMapDispatch({
        '/token': {'body': get_bearer_token()}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        authorize_url='https://i.b/authorize',
        client_kwargs={
            'code_challenge_method': 'S256',
            'app': app,
        },
    )

    async with q_app.test_request_context("/"):
        resp = await client.authorize_redirect(redirect_uri='https://b.com/bar')
        assert resp.status_code == 302

        url = resp.headers.get('Location')
        assert 'code_challenge=' in url
        assert 'code_challenge_method=S256' in url

        state = dict(url_decode(urlparse.urlparse(url).query))['state']
        sess = session[f'_state_dev_{state}']
        state_data = sess['data']

        verifier = state_data['code_verifier']
        assert verifier is not None

    path = '/?code=a&state={}'.format(state)
    async with q_app.test_request_context(path=path):
        # session is cleared in tests
        session[f'_state_dev_{state}'] = sess
        token = await client.authorize_access_token()
        assert token['access_token'] == 'a'


@pytest.mark.asyncio
async def test_with_fetch_token_in_register():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    async def fetch_token(request):
        return get_bearer_token()

    app = AsyncPathMapDispatch({
        '/user': {'body': {'sub': '123'}}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        authorize_url='https://i.b/authorize',
        fetch_token=fetch_token,
        client_kwargs={
            'app': app,
        }
    )

    # TODO: if this is required, what should it be and why?
    req = "some truthy object"
    async with q_app.test_request_context("/"):
        resp = await client.get('/user', request=req)
        assert resp.json()['sub'] == '123'

        # TODO: need to trigger ctx.authlib_client_oauth_token ????
        resp = await client.get('/user', request=req)
        assert resp.json()['sub'] == '123'


@pytest.mark.asyncio
async def test_with_fetch_token_in_oauth():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    async def fetch_token(name, request):
        return get_bearer_token()
    oauth.init_app(q_app, fetch_token=fetch_token)

    app = AsyncPathMapDispatch({
        '/user': {'body': {'sub': '123'}}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        authorize_url='https://i.b/authorize',
        client_kwargs={
            'app': app,
        }
    )

    # TODO: if this is required, what should it be and why?
    req = "some truthy object"
    async with q_app.test_request_context("/"):
        resp = await client.get('/user', request=req)
        assert resp.json()['sub'] == '123'

        # TODO: need to trigger ctx.authlib_client_oauth_token ????
        resp = await client.get('/user', request=req)
        assert resp.json()['sub'] == '123'


@pytest.mark.asyncio
async def test_request_withhold_token():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    app = AsyncPathMapDispatch({
        '/user': {'body': {'sub': '123'}}
    })
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={
            'app': app,
        }
    )

    async with q_app.test_request_context("/"):
        resp = await client.get('/user', withhold_token=True)
        assert resp.json()['sub'] == '123'


@pytest.mark.asyncio
async def test_oauth2_authorize_no_url():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
    )
    async with q_app.test_request_context("/"):
        with pytest.raises(RuntimeError):
            await client.create_authorization_url()


@pytest.mark.asyncio
async def test_oauth2_authorize_with_metadata():
    q_app = Quart(__name__)
    q_app.secret_key = "!"
    oauth = OAuth()
    oauth.init_app(q_app)
    app = AsyncPathMapDispatch({
        '/.well-known/openid-configuration': {'body': {
            'authorization_endpoint': 'https://i.b/authorize'
        }}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        api_base_url='https://i.b/api',
        access_token_url='https://i.b/token',
        server_metadata_url='https://i.b/.well-known/openid-configuration',
        client_kwargs={
            'app': app,
        }
    )
    async with q_app.test_request_context("/"):
        resp = await client.authorize_redirect('https://b.com/bar')
        assert resp.status_code == 302
