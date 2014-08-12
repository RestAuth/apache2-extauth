#!/home/mati/git/restauth/RestAuthClient/py3/bin/python

from __future__ import print_function

import os
import sys

os.environ['PYTHONPATH'] = '/home/mati/git/restauth/RestAuthCommon/python'
sys.path.insert(0, '/home/mati/git/restauth/RestAuthCommon/python')
from configparser import ConfigParser

from RestAuthClient.restauth_user import User
from RestAuthClient.common import RestAuthConnection

username = sys.stdin.readline().strip("\n")
line2 = sys.stdin.readline().strip("\n")

config = ConfigParser()
config.read([
    '/etc/restauth-extauth.conf',
    os.path.expanduser(os.path.join('~', '.restauth-extauth.conf')),
    os.path.join(os.path.dirname(sys.argv[0]), 'restauth-extauth.conf'),
])

section = os.environ.get('CONTEXT', 'restauth')

conn = RestAuthConnection(
    config.get(section, 'server'),
    config.get(section, 'user'),
    config.get(section, 'password'),
)
user = User(conn, username)
authtype = os.environ.get('AUTHTYPE', 'PASS').lower()

if authtype == 'pass':
    if user.verify_password(line2):
        sys.exit(0)
    else:
        sys.exit(1)
elif authtype == 'group':
    if user.in_group(line2):
        sys.exit(0)
    else:
        sys.exit(1)
