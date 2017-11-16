# coding: utf-8

from werkzeug.contrib.cache import (
    NullCache, SimpleCache, FileSystemCache,
    MemcachedCache, RedisCache,
)


class Missing(object):
    pass


_missing = Missing()


class Cache(object):
    """Cache module based on werkzeug.contrib.cache. This is a mixed
    version of NullCache, SimpleCache, FileSystemCache, MemcachedCache,
    and RedisCache.

    :param app: Flask app instance.
    :param config_prefix: Define a prefix for Flask app config.
    :param kwargs: Extra parameters.

    You need to configure a type of the cache, and its related configurations.
    The default ``config_prefix`` is ``AUTHLIB``, so it requires a config of::

        AUTHLIB_CACHE_TYPE = 'simple'

    If ``config_prefix`` is something else, like ``EXAMPLE``, it would be::

        EXAMPLE_CACHE_TYPE = 'simple'

    The available cache types are:

    * null: It will not cache anything. No configuration.

    * simple: It caches things in memory.
      The only configuration is ``threshold``::

          AUTHLIB_CACHE_THRESHOLD = 500

    * memcache: It caches things in Memcache. Available configurations::

          AUTHLIB_CACHE_MEMCACHED_SERVERS = []
          AUTHLIB_CACHE_KEY_PREFIX = None

    * redis: It caches things in Redis. Available configurations::

          AUTHLIB_CACHE_REDIS_HOST = 'localhost'
          AUTHLIB_CACHE_REDIS_PORT = 6379
          AUTHLIB_CACHE_REDIS_PASSWORD = None
          AUTHLIB_CACHE_REDIS_DB = 0
          AUTHLIB_CACHE_KEY_PREFIX = None

    * filesystem: It caches things in local filesystem. Available
      configurations::

          AUTHLIB_CACHE_THRESHOLD = 500
    """
    def __init__(self, app, config_prefix='AUTHLIB', **kwargs):
        self.config_prefix = config_prefix
        self.config = app.config

        cache_type = self._config('type')
        kwargs.update(dict(
            default_timeout=self._config('DEFAULT_TIMEOUT', 100)
        ))

        if cache_type == 'null':
            self.cache = NullCache()
        elif cache_type == 'simple':
            kwargs.update(dict(threshold=self._config('threshold', 500)))
            self.cache = SimpleCache(**kwargs)
        elif cache_type == 'memcache':
            kwargs.update(dict(
                servers=self._config('MEMCACHED_SERVERS'),
                key_prefix=self._config('KEY_PREFIX', None),
            ))
            self.cache = MemcachedCache(**kwargs)
        elif cache_type == 'redis':
            kwargs.update(dict(
                host=self._config('REDIS_HOST', 'localhost'),
                port=self._config('REDIS_PORT', 6379),
                password=self._config('REDIS_PASSWORD', None),
                db=self._config('REDIS_DB', 0),
                key_prefix=self._config('KEY_PREFIX', None),
            ))
            self.cache = RedisCache(**kwargs)
        elif cache_type == 'filesystem':
            kwargs.update(dict(
                threshold=self._config('threshold', 500),
            ))
            self.cache = FileSystemCache(self._config('dir'), **kwargs)
        else:
            raise RuntimeError(
                '`%s` is not a valid cache type!' % cache_type
            )
        app.extensions[config_prefix.lower() + '_cache'] = self.cache

    def _config(self, key, default=_missing):
        key = key.upper()
        prior = '%s_CACHE_%s' % (self.config_prefix, key)
        if prior in self.config:
            return self.config[prior]
        fallback = 'CACHE_%s' % key
        if fallback in self.config:
            return self.config[fallback]
        if default is _missing:
            raise RuntimeError('%s is missing.' % prior)
        return default

    def get(self, key):
        """Look up key in the cache and return the value for it.

        :param key: the key to be looked up.
        :returns: The value if it exists and is readable, else ``None``.
        """
        return self.cache.get(key)

    def delete(self, key):
        """Delete `key` from the cache.

        :param key: the key to delete.
        :returns: Whether the key existed and has been deleted.
        """
        return self.cache.delete(key)

    def get_many(self, *keys):
        """Returns a list of values for the given keys.
        For each key a item in the list is created::

            foo, bar = cache.get_many("foo", "bar")

        Has the same error handling as :meth:`get`.

        :param keys: The function accepts multiple keys as positional
                     arguments.
        """
        return [self.cache.get(k) for k in keys]

    def get_dict(self, *keys):
        """Like :meth:`get_many` but return a dict::

            d = cache.get_dict("foo", "bar")
            foo = d["foo"]
            bar = d["bar"]

        :param keys: The function accepts multiple keys as positional
                     arguments.
        """
        return self.cache.get_dict(*keys)

    def set(self, key, value, timeout=None):
        """Add a new key/value to the cache (overwrites value, if key already
        exists in the cache).

        :param key: the key to set
        :param value: the value for the key
        :param timeout: the cache timeout for the key in seconds (if not
                        specified, it uses the default timeout). A timeout of
                        0 idicates that the cache never expires.
        :returns: ``True`` if key has been updated, ``False`` for backend
                  errors. Pickling errors, however, will raise a subclass of
                  ``pickle.PickleError``.
        """
        return self.cache.set(key, value, timeout)

    def add(self, key, value, timeout=None):
        """Works like :meth:`set` but does not overwrite the values of already
        existing keys.

        :param key: the key to set
        :param value: the value for the key
        :param timeout: the cache timeout for the key in seconds (if not
                        specified, it uses the default timeout). A timeout of
                        0 idicates that the cache never expires.
        :returns: Same as :meth:`set`, but also ``False`` for already
                  existing keys.
        """
        return self.cache.add(key, value, timeout)

    def set_many(self, mapping, timeout=None):
        """Sets multiple keys and values from a mapping.

        :param mapping: a mapping with the keys/values to set.
        :param timeout: the cache timeout for the key in seconds (if not
                        specified, it uses the default timeout). A timeout of
                        0 idicates that the cache never expires.
        :returns: Whether all given keys have been set.
        """
        return self.cache.set_many(mapping, timeout)

    def delete_many(self, *keys):
        """Deletes multiple keys at once.

        :param keys: The function accepts multiple keys as positional
                     arguments.
        :returns: Whether all given keys have been deleted.
        :rtype: boolean
        """
        return self.cache.delete_many(*keys)

    def has(self, key):
        """Checks if a key exists in the cache without returning it. This is a
        cheap operation that bypasses loading the actual data on the backend.

        This method is optional and may not be implemented on all caches.

        :param key: the key to check
        """
        return self.cache.has(key)

    def clear(self):
        """Clears the cache.  Keep in mind that not all caches support
        completely clearing the cache.

        :returns: Whether the cache has been cleared.
        """
        return self.cache.clear()

    def inc(self, key, delta=1):
        """Increments the value of a key by `delta`.  If the key does
        not yet exist it is initialized with `delta`.

        For supporting caches this is an atomic operation.

        :param key: the key to increment.
        :param delta: the delta to add.
        :returns: The new value or ``None`` for backend errors.
        """
        return self.cache.inc(key, delta=delta)

    def dec(self, key, delta=1):
        """Decrements the value of a key by `delta`.  If the key does
        not yet exist it is initialized with `-delta`.

        For supporting caches this is an atomic operation.

        :param key: the key to increment.
        :param delta: the delta to subtract.
        :returns: The new value or `None` for backend errors.
        """
        return self.cache.dec(key, delta=delta)
