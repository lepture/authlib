import pytest
from starlette.config import Config
from starlette.requests import Request
from authlib.integrations.starlette_client import OAuth
from tests.py3.utils import PathMapDispatch


def test_register_remote_app():
    oauth = OAuth()
    with pytest.raises(AttributeError):
        assert oauth.dev.name == 'dev'

    oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
    )
    assert oauth.dev.name == 'dev'
    assert oauth.dev.client_id == 'dev'


def test_register_with_config():
    config = Config(environ={'DEV_CLIENT_ID': 'dev'})
    oauth = OAuth(config)
    oauth.register('dev')
    assert oauth.dev.name == 'dev'
    assert oauth.dev.client_id == 'dev'


def test_register_with_overwrite():
    config = Config(environ={'DEV_CLIENT_ID': 'dev'})
    oauth = OAuth(config)
    oauth.register('dev', client_id='not-dev', overwrite=True)
    assert oauth.dev.name == 'dev'
    assert oauth.dev.client_id == 'dev'


@pytest.mark.asyncio
async def test_oauth1_authorize():
    oauth = OAuth()
    dispatch = PathMapDispatch({
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
            'dispatch': dispatch,
        }
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, 'https://b.com/bar')
    assert resp.status_code == 307
    url = resp.headers.get('Location')
    assert 'oauth_token=foo' in url

    req_token = req.session.get("_dev_authlib_request_token_")
    assert req_token is not None

    token = await client.authorize_access_token(req)
    assert token["oauth_token"] == "a"
