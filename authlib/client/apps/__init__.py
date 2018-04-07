# flake8: noqa

from collections import defaultdict
from authlib.deprecate import deprecate
from .base import AppFactory
from ._dropbox import dropbox
from ._facebook import facebook
from ._github import github
from ._twitter import twitter
from ._google import google

__all__ = ['register_apps', 'get_app', 'get_oauth_app']

deprecate('"authlib.client.apps" will be removed, use "loginpass" instead', '0.9')

_apps_map = {
    'dropbox': dropbox,
    'facebook': facebook,
    'github': github,
    'twitter': twitter,
    'google': google,
}

_oauth_apps = defaultdict(dict)


def register_apps(oauth, services):
    for service in services:
        if service in _apps_map:
            service = _apps_map[service]

        if isinstance(service, AppFactory):
            service.register_to(oauth)
            _oauth_apps[oauth][service.name] = service


def get_oauth_app(oauth, name):
    return _oauth_apps[oauth].get(name)


def get_app(name):
    return _apps_map.get(name)
