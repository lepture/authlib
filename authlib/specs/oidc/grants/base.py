from authlib.specs.rfc6749 import InvalidRequestError
from authlib.specs.rfc6749.util import scope_to_list


class OpenIDMixin(object):
    RESPONSE_TYPES = []

    @classmethod
    def check_authorization_endpoint(cls, request):
        return is_openid_request(request, cls.RESPONSE_TYPES)

    def prepare_authorization_request(self):
        # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        self.request._data_keys.update({
            'response_mode', 'nonce', 'display', 'prompt', 'max_age',
            'ui_locales', 'id_token_hint', 'login_hint', 'acr_values'
        })

    def validate_authorization_redirect_uri(self, client):
        if not self.redirect_uri:
            raise InvalidRequestError(
                'Missing "redirect_uri" in request.',
            )

        if not client.check_redirect_uri(self.redirect_uri):
            raise InvalidRequestError(
                'Invalid "redirect_uri" in request.',
                state=self.request.state,
            )

    def validate_nonce(self, required=False):
        if not self.request.nonce:
            if required:
                raise InvalidRequestError(
                    'Missing "nonce" in request.'
                )
            return True


def is_openid_request(request, response_types):
    if request.response_type not in response_types:
        return False
    return 'openid' in scope_to_list(request.scope)
