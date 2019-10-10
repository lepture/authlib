import pytest
from starlette.config import Config
from authlib.integrations.starlette_client import OAuth


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
