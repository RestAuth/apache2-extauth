restauth-extauth.py is a small script that provides RestAuth authentication for
HTTP basic authentication via the
[mod_authnz_external](https://code.google.com/p/mod-auth-external/) Apache2
module. The script supports user authentication and group authorization,
caching credentials via Memcache or Redis and optionally hashes passwords in
the cache.

The script is written in Python and runs unter Python3.x and Python2.7. As
such, this basic authentication solution is relatively slow. 

Installation
============

To install from git, simple clone the repository and configure Apache (see
below) to use the script inside the directory. The only dependency is
[RestAuthClient](https://python.restauth.net/#installation). 

If you want to use memcache, also install:

```
# via pip:
pip install python3-memcached
# or via apt:
apt-get install python-memcache
```

To use a redis-cache, install:

```
# via pip
pip install redis hiredis
# or via apt:
apt-get install python-redis python-hiredis
```

To hash passwords with bcrypt, install:

```
# via pip
pip install py-bcrypt
# or via apt
apt-get install python-bcrypt python3-bcrypt
```

You can also run the script inside a virtualenv. Install all necessary
dependencies inside the virtualenv and use (assuming you cloned the repository
to ``/root`` and created the virtualenv inside the git repository)

```
/root/apache2-extauth/bin/python /root/apache2-extauth/restauth-extauth.py
```

as the scripts location in the apache config (see below).

Configuration
=============

The script requires a configuration file in either
``/etc/restauth-extauth.conf``, ``~/.restauth-extauth.conf`` or
``restauth-extauth.conf`` in the same directory as the script. The git
repository contains an [example configuration
file](https://github.com/RestAuth/apache2-extauth/blob/master/restauth-extauth.conf.example).

Apache 2.4
----------

For simple user authentication, do:

```
DefineExternalAuth restauth pipe .../restauth-extauth.py

<Location />
    AuthType Basic
    AuthName RestAuth
    AuthBasicProvider external
    AuthExternal restauth
    Require valid-user
</Location>
```

If you want to require groups as well, do:

```
DefineExternalAuth restauth pipe .../restauth-extauth.py
DefineExternalGroup restauth pipe .../restauth-extauth.py

<Location />
    AuthType Basic
    AuthName RestAuth
    AuthBasicProvider external
    AuthExternal restauth
    GroupExternal restauth
    <RequireAll>
        Require valid-user
        Require external-group testgroup
    </RequireAll>
</Location>
```

Apache 2.2
----------

Performance
===========

As mentioned in the introduction, using this script is quite slow. The main
bottleneck is Python's interpreter startup speed as well as excessive imports
in the libraries used by the script.

It turns out that memcache is a faster cache then redis in many scenarios.

Test
====

Use ``curl`` or ``wget`` to test authentication:

```
curl -sL -w "%{http_code}\n"  http://localhost -o /dev/null --user test:foobar
```

or:

```
wget http://localhost/index.php -O - --auth-no-challenge --http-user=user --http-password=nopass
```
