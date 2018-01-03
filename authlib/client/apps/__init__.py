# flake8: noqa

from .base import AppFactory
from .dropbox import dropbox
from .facebook import facebook, facebook_fetch_user
from .github import github
from .twitter import twitter
from .google import google

_SERVICES_MAP = {
    'dropbox': dropbox,
    'facebook': facebook,
    'github': github,
    'twitter': twitter,
    'google': google,
}


def register_to(oauth, services):
    for service in services:
        if service in _SERVICES_MAP:
            _SERVICES_MAP[service].register_to(oauth)
        elif isinstance(service, AppFactory):
            service.register_to(oauth)


def instance(name):
    return _SERVICES_MAP.get(name)
