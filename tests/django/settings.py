SECRET_KEY = 'django-secret'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "example.sqlite",
    }
}

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware'
]

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

INSTALLED_APPS=[
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'tests.django.test_oauth1',
    'tests.django.test_oauth2',
]

AUTHLIB_OAUTH_CLIENTS = {
    'dev_overwrite': {
        'client_id': 'dev-client-id',
        'client_secret': 'dev-client-secret',
        'access_token_params': {
            'foo': 'foo-1',
            'bar': 'bar-2'
        }
    }
}
