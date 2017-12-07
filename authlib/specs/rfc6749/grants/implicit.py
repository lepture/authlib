from .base import BaseGrant


class ImplicitGrant(BaseGrant):
    AUTHORIZATION_ENDPOINT = True

    @staticmethod
    def check_authorization_endpoint(params):
        return params.get('response_type') == 'token'
