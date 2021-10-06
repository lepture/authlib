name = 'authlib'
version = '1.0.2'
author = 'Quartic.ai Engineering Team'
homepage = 'https://github.com/Quarticai/authlib'

default_user_agent = '{}/{} (+{})'.format(name, version, homepage)

default_json_headers = [
    ('Content-Type', 'application/json'),
    ('Cache-Control', 'no-store'),
    ('Pragma', 'no-cache'),
]
