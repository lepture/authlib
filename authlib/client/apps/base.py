import types
import warnings
from collections import namedtuple
from authlib.common.compat import deprecate

User = namedtuple('User', ['id', 'name', 'email', 'data'])


class UserInfo(object):
    """Implementation of OpenID Connect Core `Standard Claims`_.

    .. _`Standard Claims`: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    def __init__(self, sub, name,
                 given_name=None, family_name=None, middle_name=None,
                 nickname=None, preferred_username=None,
                 profile=None, picture=None, website=None,
                 email=None, email_verified=False,
                 gender=None, birthdate=None, zoneinfo=None, locale=None,
                 phone_number=None, phone_number_verified=False,
                 address=None, updated_at=None, **kwargs):
        self.sub = sub
        self.name = name
        self.given_name = given_name
        self.family_name = family_name
        self.middle_name = middle_name
        self.nickname = nickname
        self.preferred_username = preferred_username
        self.profile = profile
        self.picture = picture
        self.website = website
        self.email = email
        self.email_verified = email_verified
        self.gender = gender
        self.birthdate = birthdate
        self.zoneinfo = zoneinfo
        self.locale = locale
        self.phone_number = phone_number
        self.phone_number_verified = phone_number_verified
        self.address = address
        self.updated_at = updated_at
        self.extras = kwargs

    def __getitem__(self, item):
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def keys(self):
        return (
            'sub', 'name', 'given_name', 'family_name', 'middle_name',
            'nickname', 'preferred_username',
            'profile', 'picture', 'website',
            'email', 'email_verified',
            'gender', 'birthdate', 'zoneinfo', 'locale',
            'phone_number', 'phone_number_verified',
            'address', 'updated_at'
        )


class AppFactory(object):
    def __init__(self, name, config, doc):
        self.name = name
        self.config = config
        self.oauth = None
        self._client = None
        self.__doc__ = doc.lstrip()

    def register_to(self, oauth):
        oauth.register(self.name, **self.config)
        self.oauth = oauth

    @property
    def client(self):
        if self._client:
            return self._client
        if self.oauth:
            self._client = self.oauth.create_client(self.name)
            return self._client
        raise RuntimeError('App not `register_to` any oauth registry')

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            return object.__getattribute__(self.client, key)


def patch_method(instance, func, name=None):
    if name is None:
        name = func.__name__
    _patch(instance, func, name)


def _patch(instance, func, name):
    setattr(instance, name, types.MethodType(func, instance))


def compatible_fetch_user(instance, profile_func):

    def fetch_user(client):
        deprecate('Use "profile()" instead of "fetch_user()"')
        info = profile_func(client)
        data = dict(info)
        return User(info.sub, name=info.name, email=info.email, data=data)

    patch_method(instance, fetch_user, 'fetch_user')
