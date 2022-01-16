import pytest
from quart import Quart

from authlib.integrations.quart_client import OAuth
from authlib.jose import jwk
from authlib.jose.errors import InvalidClaimError
from authlib.oidc.core.grants.util import generate_id_token
from tests.util import read_file_path
from tests.client_base import get_bearer_token
from ...starlette.utils import AsyncPathMapDispatch


async def run_fetch_userinfo(payload, compliance_fix=None):
    q_app = Quart(__name__)
    oauth = OAuth()
    oauth.init_app(q_app)

    app = AsyncPathMapDispatch({
        '/userinfo': {'body': payload}
    })

    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        userinfo_endpoint='https://i.b/userinfo',
        userinfo_compliance_fix=compliance_fix,
        client_kwargs={
            'app': app,
        }
    )

    user = await client.userinfo(token=get_bearer_token())
    assert user.sub == '123'


@pytest.mark.asyncio
async def test_fetch_userinfo():
    await run_fetch_userinfo({'sub': '123'})


@pytest.mark.asyncio
async def test_parse_id_token():
    key = jwk.dumps('secret', 'oct', kid='f')
    token = get_bearer_token()
    id_token = generate_id_token(
        token, {'sub': '123'}, key,
        alg='HS256', iss='https://i.b',
        aud='dev', exp=3600, nonce='n',
    )
    token['id_token'] = id_token

    q_app = Quart(__name__)
    oauth = OAuth()
    oauth.init_app(q_app)
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        fetch_token=get_bearer_token,
        jwks={'keys': [key]},
        issuer='https://i.b',
        id_token_signing_alg_values_supported=['HS256', 'RS256'],
    )
    user = await client.parse_id_token(token, nonce='n')
    assert user.sub == '123'

    claims_options = {'iss': {'value': 'https://i.b'}}
    user = await client.parse_id_token(token, nonce='n', claims_options=claims_options)
    assert user.sub == '123'

    with pytest.raises(InvalidClaimError):
        claims_options = {'iss': {'value': 'https://i.c'}}
        await client.parse_id_token(token, nonce='n', claims_options=claims_options)


@pytest.mark.asyncio
async def test_runtime_error_fetch_jwks_uri():
    key = jwk.dumps('secret', 'oct', kid='f')
    token = get_bearer_token()
    id_token = generate_id_token(
        token, {'sub': '123'}, key,
        alg='HS256', iss='https://i.b',
        aud='dev', exp=3600, nonce='n',
    )

    q_app = Quart(__name__)
    oauth = OAuth()
    oauth.init_app(q_app)
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        fetch_token=get_bearer_token,
        issuer='https://i.b',
        id_token_signing_alg_values_supported=['HS256'],
    )
    token['id_token'] = id_token
    with pytest.raises(RuntimeError, match='Missing "jwks_uri" in metadata'):
        await client.parse_id_token(token, nonce="n")


@pytest.mark.asyncio
async def test_force_fetch_jwks_uri():
    secret_keys = read_file_path('jwks_private.json')
    token = get_bearer_token()
    id_token = generate_id_token(
        token, {'sub': '123'}, secret_keys,
        alg='RS256', iss='https://i.b',
        aud='dev', exp=3600, nonce='n',
    )
    token['id_token'] = id_token

    q_app = Quart(__name__)
    oauth = OAuth()
    oauth.init_app(q_app)

    app = AsyncPathMapDispatch({
        '/jwks': {'body': read_file_path('jwks_public.json')}
    })
    client = oauth.register(
        'dev',
        client_id='dev',
        client_secret='dev',
        fetch_token=get_bearer_token,
        jwks_uri='https://i.b/jwks',
        issuer='https://i.b',
        client_kwargs={
            'app': app,
        }
    )
    user = await client.parse_id_token(token, nonce='n')
    assert user.sub == '123'
