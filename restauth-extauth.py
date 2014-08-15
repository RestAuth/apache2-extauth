#!/usr/bin/env python3

from __future__ import print_function

import os
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
})
config.read([
    '/etc/restauth-extauth.conf',
    os.path.expanduser(os.path.join('~', '.restauth-extauth.conf')),
    os.path.join(os.path.dirname(sys.argv[0]), 'restauth-extauth.conf'),
])
section = os.environ.get('CONTEXT', 'restauth')

# Append any python path
pythonpath = config.get(section, 'PYTHONPATH')
if pythonpath is not None:
    sys.path = pythonpath.split(':') + sys.path

###################
### Redis cache ###
###################
class RedisCache(object):
    def __init__(self, config, section):
        import redis
        self.conn = redis.StrictRedis(
            config.get(section, 'redis-server'),
            config.getint(section, 'redis-port'),
            config.getint(section, 'redis-db')
        )
        self.expire = config.getint(section, 'cache-expire')

    def check_password(self, user, password):
        """Check the given user and password.

        Returns None on cache miss, True if password matches, False if not.
        """
        cached = self.conn.get('%s-pass' % user)
        if cached is None:
            return cached
        else:
            return cached == bytes(password, 'utf-8')

    def set_password(self, user, password):
        self.conn.set('%s-pass' % user, password, ex=self.expire)

    def in_groups(self, user, groups):
        key = '%s-groups' % user
        if not self.conn.exists(key):
            return None

        matched = self.conn.smembers(key) & set([bytes(g, 'utf-8') for g in groups])
        if matched:
            return True
        else:
            return False

    def set_groups(self, user, groups):
        key = '%s-groups' % user
        pipe = self.conn.pipeline()
        pipe.sadd(key, *groups).expire(key, self.expire)
        pipe.execute()

# Find out if we should check a password or a group membership
authtype = os.environ.get('AUTHTYPE', 'PASS').lower()

# Query cache if configured
cache = config.get(section, 'cache')
if cache is not None:
    if cache == 'redis':
        cache = RedisCache(config, section)
    else:
        print('Unknown cache "%s".', file=sys.stderr)
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
