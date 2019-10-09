from authlib.jose import JsonWebToken, jwk
from authlib.oidc.core import UserInfo, CodeIDToken, ImplicitIDToken


class UserInfoMixin(object):
    def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``."""
        metadata = self._load_server_metadata()
        resp = self.get(metadata['userinfo_endpoint'], **kwargs)
        data = resp.json()

        compliance_fix = metadata.get('userinfo_compliance_fix')
        if compliance_fix:
            data = compliance_fix(self, data)
        return UserInfo(data)

    def _parse_id_token(self, request, token, claims_options=None):
        """Return an instance of UserInfo from token's ``id_token``."""
        if 'id_token' not in token:
            return None

        def load_key(header, payload):
            jwk_set = self._fetch_jwk_set()
            try:
                return jwk.loads(jwk_set, header.get('kid'))
            except ValueError:
                # re-try with new jwk set
                jwk_set = self._fetch_jwk_set(force=True)
                return jwk.loads(jwk_set, header.get('kid'))

        nonce = self._get_session_data(request, 'nonce')
        claims_params = dict(
            nonce=nonce,
            client_id=self.client_id,
        )
        if 'access_token' in token:
            claims_params['access_token'] = token['access_token']
            claims_cls = CodeIDToken
        else:
            claims_cls = ImplicitIDToken

        metadata = self._load_server_metadata()
        if claims_options is None and 'issuer' in metadata:
            claims_options = {'iss': {'values': [metadata['issuer']]}}

        alg_values = metadata.get('id_token_signing_alg_values_supported')
        if not alg_values:
            alg_values = ['RS256']

        jwt = JsonWebToken(alg_values)

        claims = jwt.decode(
            token['id_token'], key=load_key,
            claims_cls=claims_cls,
            claims_options=claims_options,
            claims_params=claims_params,
        )
        claims.validate(leeway=120)
        return UserInfo(claims)

    def _fetch_jwk_set(self, force=False):
        metadata = self._load_server_metadata()
        jwk_set = metadata.get('jwks')
        if jwk_set and not force:
            return jwk_set
        uri = metadata.get('jwks_uri')
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        jwk_set = self._fetch_server_metadata(uri)
        self.server_metadata['jwks'] = jwk_set
        return jwk_set
