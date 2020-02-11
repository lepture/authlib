from django.conf import settings
from django.dispatch import Signal
from django.http import HttpResponseRedirect
from ..base_client import FrameworkIntegration, RemoteApp
from ..requests_client import OAuth1Session, OAuth2Session


token_update = Signal(providing_args=['name', 'token', 'refresh_token', 'access_token'])


class DjangoIntegration(FrameworkIntegration):
    oauth1_client_cls = OAuth1Session
    oauth2_client_cls = OAuth2Session

    def update_token(self, token, refresh_token=None, access_token=None):
        token_update.send(
            sender=self.__class__,
            name=self.name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )

    def generate_access_token_params(self, request_token_url, request):
        if request_token_url:
            return request.GET.dict()

        if request.method == 'GET':
            params = {
                'code': request.GET.get('code'),
                'state': request.GET.get('state'),
            }
        else:
            params = {
                'code': request.POST.get('code'),
                'state': request.POST.get('state'),
            }
        return params

    @staticmethod
    def load_config(oauth, name, params):
        config = getattr(settings, 'AUTHLIB_OAUTH_CLIENTS', None)
        if config:
            return config.get(name)


class DjangoRemoteApp(RemoteApp):
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

    def authorize_access_token(self, request, **kwargs):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        params = self.retrieve_access_token_params(request)
        params.update(kwargs)
        return self.fetch_access_token(**params)

    def parse_id_token(self, request, token, claims_options=None):
        return self._parse_id_token(request, token, claims_options)
