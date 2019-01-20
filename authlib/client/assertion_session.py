from requests import Session
from authlib.oauth2.rfc7523 import JWTBearerGrant
from .oauth2_session import OAuth2Auth
from .errors import UnsupportedTokenTypeError


class AssertionToken(OAuth2Auth):
    def __call__(self, req):
        if not self.token or self.token.is_expired():
            self.client.refresh_token()
        try:
            req.url, req.headers, req.body = self.prepare(
                req.url, req.headers, req.body)
        except KeyError as error:
            description = 'Unsupported token_type: {}'.format(str(error))
            raise UnsupportedTokenTypeError(description=description)
        return req


class AssertionSession(Session):
    """Constructs a new Assertion Framework for OAuth 2.0 Authorization Grants
    per RFC7521_.

    .. _RFC7521: https://tools.ietf.org/html/rfc7521
    """
    JWT_BEARER_GRANT_TYPE = JWTBearerGrant.GRANT_TYPE

    ASSERTION_METHODS = {
        JWT_BEARER_GRANT_TYPE: JWTBearerGrant.sign,
    }

    def __init__(self, token_url, issuer, subject, audience, grant_type,
                 claims=None, token_placement='header', scope=None, **kwargs):
        super(AssertionSession, self).__init__()
        self.token_url = token_url
        self.grant_type = grant_type

        # https://tools.ietf.org/html/rfc7521#section-5.1
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.claims = claims
        self.scope = scope
        self.token_auth = AssertionToken(None, token_placement, self)
        self._kwargs = kwargs

    @property
    def token(self):
        return self.token_auth.token

    @token.setter
    def token(self, token):
        self.token_auth.set_token(token)

    def refresh_token(self):
        """Using Assertions as Authorization Grants to refresh token as
        described in `Section 4.1`_.

        .. _`Section 4.1`: https://tools.ietf.org/html/rfc7521#section-4.1
        """
        generate_assertion = self.ASSERTION_METHODS[self.grant_type]
        assertion = generate_assertion(
            issuer=self.issuer,
            subject=self.subject,
            audience=self.audience,
            claims=self.claims,
            **self._kwargs
        )
        data = {'assertion': assertion, 'grant_type': self.grant_type}
        if self.scope:
            data['scope'] = self.scope
        resp = self.request('POST', self.token_url, data=data, withhold_token=True)
        self.token = resp.json()
        return self.token

    def request(self, method, url, data=None, headers=None,
                withhold_token=False, auth=None, **kwargs):
        """Send request with auto refresh token feature."""
        if not withhold_token:
            if auth is None:
                auth = self.token_auth
        return super(AssertionSession, self).request(
            method, url, headers=headers, data=data, auth=auth, **kwargs)
