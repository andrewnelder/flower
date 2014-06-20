from __future__ import absolute_import

try:
    from urllib.parse import urlparse, parse_qsl, urlencode
except ImportError:
    from urlparse import urlparse, parse_qsl
    from urllib import urlencode

import re
import tornado.web
import tornado.auth

from ..auth_providers.google import GoogleOAuth2Mixin

from .. import settings
from ..views import BaseHandler

class LoginHandler(BaseHandler, GoogleOAuth2Mixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("code", None):
            authorization_code = self.get_argument("code", None)
            self.get_authenticated_user(authorization_code, self.async_callback(self._on_auth))
            return
        self.authorize_redirect(self.settings['google_permissions'])

    def _on_auth(self, response):
        #print response.body
        #print response.request.headers
        if not response:
            raise tornado.web.HTTPError(500, 'Google auth failed')
        if not re.match(self.application.auth, response['email']):
            raise tornado.web.HTTPError(
                404,
                "Access denied to '{email}'. "
                "Please use another account or ask your admin to "
                "add your email to flower --auth".format(**response))

        self.set_secure_cookie("user", str(response['email']))

        next = self.get_argument('next', '/')
        if settings.URL_PREFIX:
            next = self.absolute_url(next)

        self.redirect(next)


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('user')
        self.render('404.html', message='Successfully logged out!')
