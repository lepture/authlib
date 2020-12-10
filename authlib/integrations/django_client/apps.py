from django.http import HttpResponseRedirect
from ..base_client import OAuthError, MismatchingStateError
from ..requests_client.apps import OAuth1App, OAuth2App


class DjangoAppMixin(object):
    def save_authorize_data(self, request, **kwargs):
        state = kwargs.pop('state', None)
        if state:
            self.framework.set_state_data(request, state, kwargs)
        else:
            raise RuntimeError('Missing state value')

    def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Django view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return HttpResponseRedirect(rv['url'])


class DjangoOAuth1App(DjangoAppMixin, OAuth1App):
    def authorize_access_token(self, request, **kwargs):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        params = request.GET.dict()
        state = params.get('oauth_token')
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = self.framework.get_state_data(request, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params['request_token'] = data['request_token']
        redirect_uri = data.get('redirect_uri')
        if redirect_uri:
            params['redirect_uri'] = redirect_uri

        params.update(kwargs)
        self.framework.clear_state_data(request, state)
        return self.fetch_access_token(**params)


class DjangoOAuth2App(DjangoAppMixin, OAuth2App):
    def authorize_access_token(self, request, **kwargs):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        if request.method == 'GET':
            error = request.GET.get('error')
            if error:
                description = request.GET.get('error_description')
                raise OAuthError(error=error, description=description)
            params = {
                'code': request.GET.get('code'),
                'state': request.GET.get('state'),
            }
        else:
            params = {
                'code': request.POST.get('code'),
                'state': request.POST.get('state'),
            }

        data = self.framework.get_state_data(request, params.get('state'))
        if data is None:
            raise MismatchingStateError()

        code_verifier = data.get('code_verifier')
        if code_verifier:
            params['code_verifier'] = code_verifier

        redirect_uri = data.get('redirect_uri')
        if redirect_uri:
            params['redirect_uri'] = redirect_uri
        params.update(kwargs)
        token = self.fetch_access_token(**params)

        if 'id_token' in token and 'nonce' in params:
            userinfo = self.parse_id_token(token, nonce=params['nonce'])
            token['userinfo'] = userinfo
        return token
