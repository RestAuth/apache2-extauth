Configuration
=============

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
