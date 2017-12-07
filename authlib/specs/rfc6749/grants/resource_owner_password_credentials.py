from .base import BaseGrant


class ResourceOwnerPasswordCredentialsGrant(BaseGrant):
    ACCESS_TOKEN_ENDPOINT = True

    @staticmethod
    def check_token_endpoint(params):
        return params.get('grant_type') == 'password'
