# Embedded file name: lib\web\webopenid.py
"""openid.py: an openid library for web.py

Notes:

 - This will create a file called .openid_secret_key in the
   current directory with your secret key in it. If someone
   has access to this file they can log in as any user. And
   if the app can't find this file for any reason (e.g. you
   moved the app somewhere else) then each currently logged
   in user will get logged out.

 - State must be maintained through the entire auth process
   -- this means that if you have multiple web.py processes
   serving one set of URLs or if you restart your app often
   then log ins will fail. You have to replace sessions and
   store for things to work.

 - We set cookies starting with "openid_".

"""
from __future__ import absolute_import
import os
import random
import hmac
from . import webapi as web
import openid.consumer.consumer
import openid.store.memstore
sessions = {}
store = openid.store.memstore.MemoryStore()

def _secret():
    try:
        secret = file('.openid_secret_key').read()
    except IOError:
        secret = os.urandom(20)
        file('.openid_secret_key', 'w').write(secret)

    return secret


def _hmac(identity_url):
    return hmac.new(_secret(), identity_url).hexdigest()


def _random_session():
    n = random.random()
    while n in sessions:
        n = random.random()

    n = str(n)
    return n


def status():
    oid_hash = web.cookies().get('openid_identity_hash', '').split(',', 1)
    if len(oid_hash) > 1:
        oid_hash, identity_url = oid_hash
        if oid_hash == _hmac(identity_url):
            return identity_url
    return None


def form(openid_loc):
    oid = status()
    if oid:
        return '\n        <form method="post" action="%s">\n          <img src="http://openid.net/login-bg.gif" alt="OpenID" />\n          <strong>%s</strong>\n          <input type="hidden" name="action" value="logout" />\n          <input type="hidden" name="return_to" value="%s" />\n          <button type="submit">log out</button>\n        </form>' % (openid_loc, oid, web.ctx.fullpath)
    else:
        return '\n        <form method="post" action="%s">\n          <input type="text" name="openid" value=""\n            style="background: url(http://openid.net/login-bg.gif) no-repeat; padding-left: 18px; background-position: 0 50%%;" />\n          <input type="hidden" name="return_to" value="%s" />\n          <button type="submit">log in</button>\n        </form>' % (openid_loc, web.ctx.fullpath)


def logout():
    web.setcookie('openid_identity_hash', '', expires=-1)


class host:

    def POST(self):
        i = web.input(return_to='/')
        if i.get('action') == 'logout':
            logout()
            return web.redirect(i.return_to)
        i = web.input('openid', return_to='/')
        n = _random_session()
        sessions[n] = {'webpy_return_to': i.return_to}
        c = openid.consumer.consumer.Consumer(sessions[n], store)
        a = c.begin(i.openid)
        f = a.redirectURL(web.ctx.home, web.ctx.home + web.ctx.fullpath)
        web.setcookie('openid_session_id', n)
        return web.redirect(f)

    def GET(self):
        n = web.cookies('openid_session_id').openid_session_id
        web.setcookie('openid_session_id', '', expires=-1)
        return_to = sessions[n]['webpy_return_to']
        c = openid.consumer.consumer.Consumer(sessions[n], store)
        a = c.complete(web.input(), web.ctx.home + web.ctx.fullpath)
        if a.status.lower() == 'success':
            web.setcookie('openid_identity_hash', _hmac(a.identity_url) + ',' + a.identity_url)
        del sessions[n]
        return web.redirect(return_to)