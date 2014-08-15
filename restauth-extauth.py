#!/usr/bin/env python3

from __future__ import print_function

import hashlib
import os
import random
import sys

from configparser import ConfigParser

from RestAuthClient.restauth_user import User
from RestAuthClient.common import RestAuthConnection

# Read data from stdin
username = sys.stdin.readline().strip("\n")
line2 = sys.stdin.readline().strip("\n")

# Read configuration
config = ConfigParser({
    'PYTHONPATH': None,
    'cache': None,
    'cache-expire': '300',
    'redis-server': 'localhost',
    'redis-port': '6379',
    'redis-db': '0',
    'memcache-server': '127.0.0.1:11211',
    'password-hash': '',
})
config.read([
    '/etc/restauth-extauth.conf',
    os.path.expanduser(os.path.join('~', '.restauth-extauth.conf')),
    os.path.join(os.path.dirname(sys.argv[0]), 'restauth-extauth.conf'),
])
section = os.environ.get('CONTEXT', 'restauth')
crypt_algo = config.get(section, 'password-hash')

# Append any python path
pythonpath = config.get(section, 'PYTHONPATH')
if pythonpath is not None:
    sys.path = pythonpath.split(':') + sys.path


#######################
### Cache baseclass ###
#######################
class CacheBase(object):
    expire = config.getint(section, 'cache-expire')
    _bcrypt = None

    def prefix(self, key):
        return 'authnz-external:%s:%s' % (section, key)

    def _salt(self, length=12):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return ''.join([random.choice(chars) for i in range(length)])

    def _hash_bcrypt(self, password, salt=None):
        if self._bcrypt is None:
            import bcrypt
            self._bcrypt = bcrypt

        if salt is None:
            return bcrypt.hashpw(password, bcrypt.gensalt())
        else:
            return bcrypt.hashpw(password, salt)

    def _hash_hashlib(self, password, salt=None):
        if salt is None:
            salt = self._salt()
        else:
            salt = salt.split('$', 1)[0]

        to_hash = bytes('%s$%s' % (salt, password), 'utf-8')
        return '%s$%s' % (salt, getattr(hashlib, crypt_algo)(to_hash).hexdigest())

    def _hash_none(self, password, salt=None):
        return password

    if crypt_algo == 'bcrypt':
        hash = _hash_bcrypt
    elif hasattr(hashlib, crypt_algo):
        hash = _hash_hashlib
    elif not crypt_algo:
        hash = _hash_none
    else:
        print('Unknown password-hash %s, not hashing passwords.' % crypt_algo, file=sys.stderr)
        hash = _hash_none

###################
### Redis cache ###
###################
class RedisCache(CacheBase):
    def __init__(self, config, section):
        import redis
        self.conn = redis.StrictRedis(
            config.get(section, 'redis-server'),
            config.getint(section, 'redis-port'),
            config.getint(section, 'redis-db')
        )

    def check_password(self, user, password):
        """Check the given user and password.

        Returns None on cache miss, True if password matches, False if not.
        """
        cached = self.conn.get(self.prefix('%s-pass' % user))
        if cached is None:
            return cached
        else:
            return cached == bytes(self.hash(password, cached.decode('utf-8')), 'utf-8')

    def set_password(self, user, password):
        self.conn.set(self.prefix('%s-pass' % user), self.hash(password), ex=self.expire)

    def in_groups(self, user, groups):
        key = self.prefix('%s-groups' % user)
        if not self.conn.exists(key):
            return None

        matched = self.conn.smembers(key) & set([bytes(g, 'utf-8') for g in groups])
        if matched:
            return True
        else:
            return False

    def set_groups(self, user, groups):
        key = self.prefix('%s-groups' % user)
        pipe = self.conn.pipeline()
        pipe.sadd(key, *groups).expire(key, self.expire)
        pipe.execute()


#######################
### Memcached cache ###
#######################
class MemcachedCache(CacheBase):
    def __init__(self, config, section):
        import memcache
        self.conn = memcache.Client(config.get(section, 'memcache-server').split())

    def key(self, raw):
        return self.prefix(hashlib.md5(bytes(raw, 'utf-8')).hexdigest())

    def check_password(self, user, password):
        cached = self.conn.get(self.key('%s-pass' % user))
        if cached is None:
            return cached
        return cached == self.hash(password, cached)

    def set_password(self, user, password):
        self.conn.set(self.key('%s-pass' % user), self.hash(password), self.expire)

    def in_groups(self, user, groups):
        cached = self.conn.get(self.key('%s-groups' % user))
        if cached is None:
            return None
        return not cached.isdisjoint(set(groups))

    def set_groups(self, user, groups):
        self.conn.set(self.key('%s-groups' % user), set(groups), self.expire)


# Find out if we should check a password or a group membership
authtype = os.environ.get('AUTHTYPE', 'PASS').lower()

# Query cache if configured
cache = config.get(section, 'cache')
if cache is not None:
    if cache == 'redis':
        cache = RedisCache(config, section)
    elif cache == 'memcache':
        cache = MemcachedCache(config, section)
    else:
        print('Unknown cache "%s".' % cache, file=sys.stderr)
        sys.exit(1)

    if authtype == 'pass':
        checked = cache.check_password(username, line2)
        if checked is True:
            sys.exit(0)
        elif checked is False:
            sys.exit(1)
        # else: cache miss
    elif authtype == 'group':
        checked = cache.in_groups(username, line2.split())
        if checked is True:
            sys.exit(0)
        elif checked is False:
            sys.exit(1)
        # else: cache miss

# Setup RestAuth connection
conn = RestAuthConnection(
    config.get(section, 'server'),
    config.get(section, 'user'),
    config.get(section, 'password'),
)
user = User(conn, username)

# Actual RestAuth queries in case cache does not match
if authtype == 'pass':
    if user.verify_password(line2):
        # set in cache if defined
        if cache is not None:
            cache.set_password(username, line2)

        sys.exit(0)
    else:
        sys.exit(1)

elif authtype == 'group':
    checked = set(line2.split())
    groups = set([g.name for g in user.get_groups()])

    if checked & groups:
        if cache is not None:
            cache.set_groups(username, groups)
        sys.exit(0)
    else:
        sys.exit(1)
