from __future__ import unicode_literals, print_function
from unittest import TestCase
from flask import Flask
from werkzeug.contrib.cache import NullCache, SimpleCache
from authlib.common.flask import Cache


class FlaskCacheTest(TestCase):
    def test_cache_type(self):
        app = Flask(__name__)
        self.assertRaises(RuntimeError, Cache, app)
        app.config.update({'AUTHLIB_CACHE_TYPE': 'null'})
        c = Cache(app)
        self.assertIsInstance(c.cache, NullCache)
        app.config.update({'AUTHLIB_CACHE_TYPE': 'simple'})
        c = Cache(app)
        self.assertIsInstance(c.cache, SimpleCache)

    def test_cache_methods(self):
        app = Flask(__name__)
        app.config.update({'AUTHLIB_CACHE_TYPE': 'simple'})
        c = Cache(app)

        c.set('a', 'foo')
        self.assertTrue(c.has('a'))
        self.assertEqual(c.get('a'), 'foo')

        c.clear()
        self.assertIsNone(c.get('a'))

        c.add('a', 'foo')
        self.assertEqual(c.get('a'), 'foo')
        c.add('a', 'bar')
        self.assertEqual(c.get('a'), 'foo')
        c.set('a', 'bar')
        self.assertEqual(c.get('a'), 'bar')
        c.clear()

        c.set_many({'a': 'alice', 'b': 'bob'})
        rv = c.get_many('a', 'b')
        self.assertEqual(rv[0], 'alice')
        self.assertEqual(rv[1], 'bob')

        rv = c.get_dict('a', 'b')
        self.assertEqual(rv['a'], 'alice')

        self.assertEqual(c.inc('c'), 1)
        self.assertEqual(c.dec('c'), 0)

        c.delete_many('a', 'b', 'c')
        self.assertFalse(c.has('a'))
        self.assertFalse(c.has('b'))
        self.assertFalse(c.has('c'))
        c.clear()
