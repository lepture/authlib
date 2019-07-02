from requests import Session
from requests.auth import AuthBase
from .assertion_client import AssertionTokenAuth, AssertionClient
from .errors import UnsupportedTokenTypeError


class AssertionAuth(AuthBase, AssertionTokenAuth):
    def __call__(self, req):
        self.ensure_refresh_token()
        try:
            req.url, req.headers, req.body = self.prepare(
                req.url, req.headers, req.body)
        except KeyError as error:
            description = 'Unsupported token_type: {}'.format(str(error))
            raise UnsupportedTokenTypeError(description=description)
        return req


class AssertionSession(AssertionClient, Session):
    """Constructs a new Assertion Framework for OAuth 2.0 Authorization Grants
    per RFC7521_.

    .. _RFC7521: https://tools.ietf.org/html/rfc7521
    """
    token_auth_class = AssertionAuth

    def __init__(self, token_url, issuer, subject, audience, grant_type=None,
                 claims=None, token_placement='header', scope=None, **kwargs):
        Session.__init__(self)
        AssertionClient.__init__(
            self, session=self,
            token_url=token_url, issuer=issuer, subject=subject,
            audience=audience, grant_type=grant_type, claims=claims,
            token_placement=token_placement, scope=scope, **kwargs
        )

    def request(self, method, url, data=None, headers=None,
                withhold_token=False, auth=None, **kwargs):
        """Send request with auto refresh token feature."""
        if not withhold_token and auth is None:
            auth = self.token_auth
        return super(AssertionSession, self).request(
            method, url, headers=headers, data=data, auth=auth, **kwargs)
