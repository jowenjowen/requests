# -*- coding: utf-8 -*-

"""Tests for Requests."""

from __future__ import division
import json
import pickle
import collections
import contextlib
import warnings
import re
import requests

import io
import pytest
from requests.domain import HTTPAdapter
from requests.domain import HTTPDigestAuth
from requests.domain import Auth
from requests.x import XCookieJar
from requests.x import XDefaultCookiePolicy
from requests.x import XOs
from requests.domain import XMorsel
from requests.domain import XCompat

from requests.domain import CookieUtils
from requests import exceptions
from requests.domain import CookieConflictError
from requests.domain import PreparedRequest
from requests.domain import CaseInsensitiveDict
from requests.domain import SessionRedirectMixin
from requests.domain import Hooks, Utils
from requests.domain import XMutableMapping
from requests.domain import CookieJar
from requests.domain import Request
from requests.domain import Session
from requests.domain import Requests
from requests.domain import Response
from requests.domain import AuthBase

from .compat import CompatStringIO, u
from .utils import override_environ
from urllib3.util import Timeout as Urllib3Timeout

# Requests to this URL should always fail with a connection timeout (nothing
# listening on that port)
TARPIT = 'http://10.255.255.1'

# This is to avoid waiting the timeout of using TARPIT
INVALID_PROXY='http://localhost:1'

try:
    from ssl import SSLContext
    del SSLContext
    HAS_MODERN_SSL = True
except ImportError:
    HAS_MODERN_SSL = False

try:
    requests.pyopenssl
    HAS_PYOPENSSL = True
except AttributeError:
    HAS_PYOPENSSL = False


class TestRequests:

    digest_auth_algo = ('MD5', 'SHA-256', 'SHA-512')

    def test_entry_points(self):

        Session
        Session().get
        Session().head
        Requests().get
        Requests().head
        Requests().put
        Requests().patch
        Requests().post
        # Not really an entry point, but people rely on it.
        # from Requests().domain.Packages().urllib3.poolmanager import PoolManager

    @pytest.mark.parametrize(
        'exception, url', (
            (exceptions.MissingSchema, 'hiwpefhipowhefopw'),
            (exceptions.InvalidSchema, 'localhost:3128'),
            (exceptions.InvalidSchema, 'localhost.localdomain:3128/'),
            (exceptions.InvalidSchema, '10.122.1.1:3128/'),
            (exceptions.InvalidURL, 'http://'),
        ))
    def test_invalid_url(self, exception, url):
        with pytest.raises(exception):
            Requests().get(url)

    def test_basic_building(self):
        pr = Request().url_('http://kennethreitz.org/').data_({'life': '42'}).prepare()
        assert pr.url_() == 'http://kennethreitz.org/'
        assert pr.body_() == 'life=42'

    @pytest.mark.parametrize('method', ('GET', 'HEAD'))
    def test_no_content_length(self, httpbin, method):
        req = Request().method_(method).url_(httpbin(method.lower())).prepare()
        assert 'Content-Length' not in req.headers_()

    @pytest.mark.parametrize('method', ('POST', 'PUT', 'PATCH', 'OPTIONS'))
    def test_no_body_content_length(self, httpbin, method):
        req = Request().method_(method).url_(httpbin(method.lower())).prepare()
        assert req.headers_()['Content-Length'] == '0'

    @pytest.mark.parametrize('method', ('POST', 'PUT', 'PATCH', 'OPTIONS'))
    def test_empty_content_length(self, httpbin, method):
        req = Request().method_(method).url_(httpbin(method.lower())).data_('').prepare()
        assert req.headers_()['Content-Length'] == '0'

    def test_override_content_length(self, httpbin):
        r = Request().method_('POST').url_(httpbin('post')).add_header('Content-Length', 'not zero').prepare()
        assert 'Content-Length' in r.headers_()
        assert r.headers_()['Content-Length'] == 'not zero'

    def test_path_is_not_double_encoded(self):
        request = Request().method_('GET').url_("http://0.0.0.0/get/test case").prepare()

        assert request.path_url == '/get/test%20case'

    @pytest.mark.parametrize(
        'url, expected', (
            ('http://example.com/path#fragment', 'http://example.com/path?a=b#fragment'),
            ('http://example.com/path?key=value#fragment', 'http://example.com/path?key=value&a=b#fragment')
        ))
    def test_params_are_added_before_fragment(self, url, expected):
        request = Request().method_('GET').url_(url).params_({"a": "b"}).prepare()
        assert request.url_() == expected

    def test_params_original_order_is_preserved_by_default(self):
        session = Session()
        request = Request().method_('GET').url_('http://example.com/').params_(
            collections.OrderedDict((('z', 1), ('a', 1), ('k', 1), ('d', 1))))
        prep = session.prepare_request(request)
        assert prep.url_() == 'http://example.com/?z=1&a=1&k=1&d=1'

    def test_params_bytes_are_encoded(self):
        request = Request().method_('GET').url_('http://example.com').params_(b'test=foo').prepare()
        assert request.url_() == 'http://example.com/?test=foo'

    def test_binary_put(self):
        request = Request().method_('PUT').url_('http://example.com').data_(u"ööö".encode("utf-8")).prepare()
        assert isinstance(request.body_(), bytes)

    def test_whitespaces_are_removed_from_url(self):
        # Test for issue #3696
        request = Request().method_('GET').url_(' http://example.com').prepare()
        assert request.url_() == 'http://example.com/'

    @pytest.mark.parametrize('scheme', ('http://', 'HTTP://', 'hTTp://', 'HttP://'))
    def test_mixed_case_scheme_acceptable(self, httpbin, scheme):
        s = Session().proxies_(XCompat().getproxies())
        parts = XCompat().urlparse(httpbin('get'))
        url = scheme + parts.netloc + parts.path
        r = s.send(Request().method_('GET').url_(url).prepare())
        assert r.status_code_() == 200, 'failed for scheme {}'.format(scheme)

    def test_HTTP_200_OK_GET_ALTERNATIVE(self, httpbin):
        r = Request().method_('GET').url_(httpbin('get'))
        resp = Session().proxies_(XCompat().getproxies()).send(r.prepare())
        assert resp.status_code_() == 200

    def test_HTTP_302_ALLOW_REDIRECT_GET(self, httpbin):
        r = Requests().get(httpbin('redirect', '1'))
        assert r.status_code_() == 200
        assert r.history_()[0].status_code_() == 302
        assert r.history_()[0].is_redirect()

    def test_HTTP_307_ALLOW_REDIRECT_POST(self, httpbin):
        r = Requests().post(httpbin('redirect-to'), data='test', params={'url': 'post', 'status_code': 307})
        assert r.status_code_() == 200
        assert r.history_()[0].status_code_() == 307
        assert r.history_()[0].is_redirect()
        assert r.json()['data'] == 'test'

    def test_HTTP_307_ALLOW_REDIRECT_POST_WITH_SEEKABLE(self, httpbin):
        byte_str = b'test'
        r = Requests().post(httpbin('redirect-to'), data=io.BytesIO(byte_str), params={'url': 'post', 'status_code': 307})
        assert r.status_code_() == 200
        assert r.history_()[0].status_code_() == 307
        assert r.history_()[0].is_redirect()
        assert r.json()['data'] == byte_str.decode('utf-8')

    def test_HTTP_302_TOO_MANY_REDIRECTS(self, httpbin):
        try:
            Requests().get(httpbin('relative-redirect', '50'))
        except exceptions.TooManyRedirects as e:
            url = httpbin('relative-redirect', '20')
            assert e.request.url_() == url
            assert e.response.url_() == url
            assert len(e.response.history_()) == 30
        else:
            pytest.fail('Expected redirect to raise exceptions.TooManyRedirects but it did not')

    def test_HTTP_302_TOO_MANY_REDIRECTS_WITH_PARAMS(self, httpbin):
        s = Session()
        s.max_redirects_(5)
        try:
            s.get(httpbin('relative-redirect', '50'))
        except exceptions.TooManyRedirects as e:
            url = httpbin('relative-redirect', '45')
            assert e.request.url_() == url
            assert e.response.url_() == url
            assert len(e.response.history_()) == 5
        else:
            pytest.fail('Expected custom max number of redirects to be respected but was not')

    def test_http_301_changes_post_to_get(self, httpbin):
        r = Requests().post(httpbin('status', '301'))
        assert r.status_code_() == 200
        assert r.request_().method_() == 'GET'
        assert r.history_()[0].status_code_() == 301
        assert r.history_()[0].is_redirect()

    def test_http_301_doesnt_change_head_to_get(self, httpbin):
        r = Requests().head(httpbin('status', '301'), allow_redirects=True)
        print(r.content_())
        assert r.status_code_() == 200
        assert r.request_().method_() == 'HEAD'
        assert r.history_()[0].status_code_() == 301
        assert r.history_()[0].is_redirect()

    def test_http_302_changes_post_to_get(self, httpbin):
        r = Requests().post(httpbin('status', '302'))
        assert r.status_code_() == 200
        assert r.request_().method_() == 'GET'
        assert r.history_()[0].status_code_() == 302
        assert r.history_()[0].is_redirect()

    def test_http_302_doesnt_change_head_to_get(self, httpbin):
        r = Requests().head(httpbin('status', '302'), allow_redirects=True)
        assert r.status_code_() == 200
        assert r.request_().method_() == 'HEAD'
        assert r.history_()[0].status_code_() == 302
        assert r.history_()[0].is_redirect()

    def test_http_303_changes_post_to_get(self, httpbin):
        r = Requests().post(httpbin('status', '303'))
        assert r.status_code_() == 200
        assert r.request_().method_() == 'GET'
        assert r.history_()[0].status_code_() == 303
        assert r.history_()[0].is_redirect()

    def test_http_303_doesnt_change_head_to_get(self, httpbin):
        r = Requests().head(httpbin('status', '303'), allow_redirects=True)
        assert r.status_code_() == 200
        assert r.request_().method_() == 'HEAD'
        assert r.history_()[0].status_code_() == 303
        assert r.history_()[0].is_redirect()

    def test_header_and_body_removal_on_redirect(self, httpbin):
        purged_headers = ('Content-Length', 'Content-Type')
        ses = Session()
        req = Request().method_('POST').url_(httpbin('post')).data_({'test': 'data'})
        prep = ses.prepare_request(req)
        resp = ses.send(prep)

        # Mimic a redirect response
        resp.status_code_(302)
        resp.headers_()['location'] = 'get'

        # Run request through resolve_redirects
        next_resp = next(ses.resolve_redirects(resp, prep))
        assert next_resp.request_().body_() is None
        for header in purged_headers:
            assert header not in next_resp.request_().headers_()

    def test_transfer_enc_removal_on_redirect(self, httpbin):
        purged_headers = ('Transfer-Encoding', 'Content-Type')
        ses = Session()
        req = Request().method_('POST').url_(httpbin('post')).data_((b'x' for x in range(1)))
        prep = ses.prepare_request(req)
        assert 'Transfer-Encoding' in prep.headers_()

        # Create Response to avoid https://github.com/kevin1024/pytest-httpbin/issues/33
        resp = Response()
        resp.raw_(io.BytesIO(b'the content'))
        resp.request_(prep)
        setattr(resp.raw_(), 'release_conn', lambda *args: args)

        # Mimic a redirect response
        resp.status_code_(302)
        resp.headers_()['location'] = httpbin('get')

        # Run request through resolve_redirect
        next_resp = next(ses.resolve_redirects(resp, prep))
        assert next_resp.request_().body_() is None
        for header in purged_headers:
            assert header not in next_resp.request_().headers_()

    def test_fragment_maintained_on_redirect(self, httpbin):
        fragment = "#view=edit&token=hunter2"
        r = Requests().get(httpbin('redirect-to?url=get')+fragment)

        assert len(r.history_()) > 0
        assert r.history_()[0].request_().url_() == httpbin('redirect-to?url=get')+fragment
        assert r.url_() == httpbin('get')+fragment

    def test_HTTP_200_OK_GET_WITH_PARAMS(self, httpbin):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = Requests().get(httpbin('user-agent'), headers=heads)

        assert heads['User-agent'] in r.text
        assert r.status_code_() == 200

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self, httpbin):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = Requests().get(httpbin('get') + '?test=true', params={'q': 'test'}, headers=heads)
        assert r.status_code_() == 200

    def test_set_cookie_on_301(self, httpbin):
        s = Session()
        url = httpbin('cookies/set?foo=bar')
        s.get(url)
        assert s.cookies_()['foo'] == 'bar'

    def test_cookie_sent_on_redirect(self, httpbin):
        s = Session()
        s.get(httpbin('cookies/set?foo=bar'))
        r = s.get(httpbin('redirect/1'))  # redirects to httpbin('get')
        assert 'Cookie' in r.json()['headers']

    def test_cookie_removed_on_expire(self, httpbin):
        s = Session()
        s.get(httpbin('cookies/set?foo=bar'))
        assert s.cookies_()['foo'] == 'bar'
        s.get(
            httpbin('response-headers'),
            params={
                'Set-Cookie':
                    'foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT'
            }
        )
        assert 'foo' not in s.cookies_()

    def test_cookie_quote_wrapped(self, httpbin):
        s = Session()
        s.get(httpbin('cookies/set?foo="bar:baz"'))
        assert s.cookies_()['foo'] == '"bar:baz"'

    def test_cookie_persists_via_api(self, httpbin):
        s = Session()
        r = s.get(httpbin('redirect/1'), cookies={'foo': 'bar'})
        assert 'foo' in r.request_().headers_()['Cookie']
        assert 'foo' in r.history_()[0].request_().headers_()['Cookie']

    def test_request_cookie_overrides_session_cookie(self, httpbin):
        s = Session()
        s.cookies_()['foo'] = 'bar'
        r = s.get(httpbin('cookies'), cookies={'foo': 'baz'})
        assert r.json()['cookies']['foo'] == 'baz'
        # Session cookie should not be modified
        assert s.cookies_()['foo'] == 'bar'

    def test_request_cookies_not_persisted(self, httpbin):
        s = Session()
        s.get(httpbin('cookies'), cookies={'foo': 'baz'})
        # Sending a request with cookies should not add cookies to the session
        assert not s.cookies_()

    def test_generic_cookiejar_works(self, httpbin):
        cj = XCookieJar()
        CookieUtils().cookiejar_from_dict({'foo': 'bar'}, cj)
        s = Session()
        s.cookies_(cj)
        r = s.get(httpbin('cookies'))
        # Make sure the cookie was sent
        assert r.json()['cookies']['foo'] == 'bar'
        # Make sure the session cj is still the custom one
        assert s.cookies_() is cj

    def test_param_cookiejar_works(self, httpbin):
        cj = XCookieJar()
        CookieUtils().cookiejar_from_dict({'foo': 'bar'}, cj)
        s = Session()
        r = s.get(httpbin('cookies'), cookies=cj)
        # Make sure the cookie was sent
        assert r.json()['cookies']['foo'] == 'bar'

    def test_cookielib_cookiejar_on_redirect(self, httpbin):
        """Tests resolve_redirect doesn't fail when merging cookies
        with XCookieJar.

        See GH #3579
        """
        cj = CookieUtils().cookiejar_from_dict({'foo': 'bar'}, XCookieJar())
        s = Session()
        s.cookies_(CookieUtils().cookiejar_from_dict({'cookie': 'tasty'}))

        # Prepare request without using Session
        prep_req = Request().method_('GET').url_(httpbin('headers')).cookies_(cj).prepare()

        # Send request and simulate redirect
        resp = s.send(prep_req)
        resp.status_code_(302)
        resp.headers_()['location'] = httpbin('get')
        redirects = s.resolve_redirects(resp, prep_req)
        resp = next(redirects)

        # Verify XCookieJar isn't being converted to CookieJar
        assert isinstance(prep_req._cookies, XCookieJar)
        assert isinstance(resp.request_()._cookies, XCookieJar)
        assert not isinstance(resp.request_()._cookies, CookieJar)

        cookies = {}
        for c in resp.request_()._cookies:
            cookies[c.name] = c.value
        assert cookies['foo'] == 'bar'
        assert cookies['cookie'] == 'tasty'

    def test_requests_in_history_are_not_overridden(self, httpbin):
        resp = Requests().get(httpbin('redirect/3'))
        urls = [r.url_() for r in resp.history_()]
        req_urls = [r.request_().url_() for r in resp.history_()]
        assert urls == req_urls

    def test_history_is_always_a_list(self, httpbin):
        """Show that even with redirects, Response.history_() is always a list."""
        resp = Requests().get(httpbin('get'))
        assert isinstance(resp.history_(), list)
        resp = Requests().get(httpbin('redirect/1'))
        assert isinstance(resp.history_(), list)
        assert not isinstance(resp.history_(), tuple)

    def test_headers_on_session_with_None_are_not_sent(self, httpbin):
        """Do not send headers in Session.headers with None values."""
        ses = Session()
        ses.headers_()['Accept-Encoding'] = None
        req = Request().method_('GET').url_(httpbin('get'))
        prep = ses.prepare_request(req)
        assert 'Accept-Encoding' not in prep.headers_()

    def test_headers_preserve_order(self, httpbin):
        """Preserve order when headers provided as OrderedDict."""
        ses = Session()
        ses.headers_(collections.OrderedDict())
        ses.headers_()['Accept-Encoding'] = 'identity'
        ses.headers_()['First'] = '1'
        ses.headers_()['Second'] = '2'
        headers = collections.OrderedDict([('Third', '3'), ('Fourth', '4')])
        headers['Fifth'] = '5'
        headers['Second'] = '222'
        prep = ses.prepare_request(Request().method_('GET').url_(httpbin('get')).headers_(headers))
        items = list(prep.headers_().items())
        assert items[0] == ('Accept-Encoding', 'identity')
        assert items[1] == ('First', '1')
        assert items[2] == ('Second', '222')
        assert items[3] == ('Third', '3')
        assert items[4] == ('Fourth', '4')
        assert items[5] == ('Fifth', '5')

    @pytest.mark.parametrize('key', ('User-agent', 'user-agent'))
    def test_user_agent_transfers(self, httpbin, key):

        heads = {key: 'Mozilla/5.0 (github.com/psf/requests)'}

        r = Requests().get(httpbin('user-agent'), headers=heads)
        assert heads[key] in r.text

    def test_HTTP_200_OK_HEAD(self, httpbin):
        r = Requests().head(httpbin('get'))
        assert r.status_code_() == 200

    def test_HTTP_200_OK_PUT(self, httpbin):
        r = Requests().put(httpbin('put'))
        assert r.status_code_() == 200

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self, httpbin):
        auth = ('user', 'pass')
        url = httpbin('basic-auth', 'user', 'pass')

        r = Requests().get(url, auth=auth)
        assert r.status_code_() == 200

        r = Requests().get(url)
        assert r.status_code_() == 401

        s = Session()
        s.auth_(auth)
        r = s.get(url)
        assert r.status_code_() == 200

    @pytest.mark.parametrize(
        'username, password', (
            ('user', 'pass'),
            (u'имя'.encode('utf-8'), u'пароль'.encode('utf-8')),
            (42, 42),
            (None, None),
        ))
    def test_set_basicauth(self, httpbin, username, password):
        p = Request().method_('GET').url_(httpbin('get')).auth_((username, password)).prepare()
        assert p.headers_()['Authorization'] == Auth().basic_auth_str(username, password)

    def test_basicauth_encodes_byte_strings(self):
        """Ensure b'test' formats as the byte string "test" rather
        than the unicode string "b'test'" in Python 3.
        """
        p = Request().method_('GET').url_('http://localhost').auth_((b'\xc5\xafsername', b'test\xc6\xb6')).prepare()
        assert p.headers_()['Authorization'] == 'Basic xa9zZXJuYW1lOnRlc3TGtg=='

    @pytest.mark.parametrize(
        'url, exception', (
            # Connecting to an unknown domain should raise a exceptions.ConnectionError
            ('http://doesnotexist.google.com', exceptions.ConnectionError),
            # Connecting to an invalid port should raise a exceptions.ConnectionError
            ('http://localhost:1', exceptions.ConnectionError),
            # Inputing a URL that cannot be parsed should raise an exceptions.InvalidURL error
            ('http://fe80::5054:ff:fe5a:fc0', exceptions.InvalidURL)
        ))
    def test_errors(self, url, exception):
        with pytest.raises(exception):
            Requests().get(url, timeout=1)

    def test_proxy_error(self):
        # any proxy related error (address resolution, no route to host, etc) should result in a exceptions.ProxyError
        with pytest.raises(exceptions.ProxyError):
            Requests().get('http://localhost:1', proxies={'http': 'non-resolvable-address'})

    def test_proxy_error_on_bad_url(self, httpbin, httpbin_secure):
        with pytest.raises(exceptions.InvalidProxyURL):
            Requests().get(httpbin_secure(), proxies={'https': 'http:/badproxyurl:3128'})

        with pytest.raises(exceptions.InvalidProxyURL):
            Requests().get(httpbin(), proxies={'http': 'http://:8080'})

        with pytest.raises(exceptions.InvalidProxyURL):
            Requests().get(httpbin_secure(), proxies={'https': 'https://'})

        with pytest.raises(exceptions.InvalidProxyURL):
            Requests().get(httpbin(), proxies={'http': 'http:///example.com:8080'})

    def test_respect_proxy_env_on_send_self_prepared_request(self, httpbin):
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(exceptions.ProxyError):
                session = Session()
                request = Request().method_('GET').url_(httpbin())
                session.send(request.prepare())

    def test_respect_proxy_env_on_send_session_prepared_request(self, httpbin):
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(exceptions.ProxyError):
                session = Session()
                request = Request().method_('GET').url_(httpbin())
                prepared = session.prepare_request(request)
                session.send(prepared)

    def test_respect_proxy_env_on_send_with_redirects(self, httpbin):
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(exceptions.ProxyError):
                session = Session()
                url = httpbin('redirect/1')
                print(url)
                request = Request().method_('GET').url_(url)
                session.send(request.prepare())

    def test_respect_proxy_env_on_get(self, httpbin):
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(exceptions.ProxyError):
                session = Session()
                session.get(httpbin())

    def test_respect_proxy_env_on_request(self, httpbin):
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(exceptions.ProxyError):
                session = Session()
                session.request(method='GET', url=httpbin())

    def test_proxy_authorization_preserved_on_request(self, httpbin):
        proxy_auth_value = "Bearer XXX"
        session = Session()
        session.headers_().update({"Proxy-Authorization": proxy_auth_value})
        resp = session.request(method='GET', url=httpbin('get'))
        sent_headers = resp.json().get('headers', {})

        assert sent_headers.get("Proxy-Authorization") == proxy_auth_value

    def test_basicauth_with_netrc(self, httpbin):
        auth = ('user', 'pass')
        wrong_auth = ('wronguser', 'wrongpass')
        url = httpbin('basic-auth', 'user', 'pass')

        old_auth = Utils().get_netrc_auth

        try:
            def get_netrc_auth_mock(self, url):
                return auth
            Utils.get_netrc_auth = get_netrc_auth_mock

            # Should use netrc and work.
            r = Requests().get(url)
            assert r.status_code_() == 200

            # Given auth should override and fail.
            r = Requests().get(url, auth=wrong_auth)
            assert r.status_code_() == 401

            s = Session()

            # Should use netrc and work.
            r = s.get(url)
            assert r.status_code_() == 200

            # Given auth should override and fail.
            s.auth_(wrong_auth)
            r = s.get(url)
            assert r.status_code_() == 401
        finally:
            Utils.get_netrc_auth = old_auth

    def test_DIGEST_HTTP_200_OK_GET(self, httpbin):

        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth('user', 'pass')
            url = httpbin('digest-auth', 'auth', 'user', 'pass', authtype, 'never')

            r = Requests().get(url, auth=auth)
            assert r.status_code_() == 200

            r = Requests().get(url)
            assert r.status_code_() == 401
            print(r.headers_()['WWW-Authenticate'])

            s = Session()
            s.auth_(HTTPDigestAuth('user', 'pass'))
            r = s.get(url)
            assert r.status_code_() == 200

    def test_DIGEST_AUTH_RETURNS_COOKIE(self, httpbin):

        for authtype in self.digest_auth_algo:
            url = httpbin('digest-auth', 'auth', 'user', 'pass', authtype)
            auth = HTTPDigestAuth('user', 'pass')
            r = Requests().get(url)
            assert r.cookies_()['fake'] == 'fake_value'

            r = Requests().get(url, auth=auth)
            assert r.status_code_() == 200

    def test_DIGEST_AUTH_SETS_SESSION_COOKIES(self, httpbin):

        for authtype in self.digest_auth_algo:
            url = httpbin('digest-auth', 'auth', 'user', 'pass', authtype)
            auth = HTTPDigestAuth('user', 'pass')
            s = Session()
            s.get(url, auth=auth)
            assert s.cookies_()['fake'] == 'fake_value'

    def test_DIGEST_STREAM(self, httpbin):

        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth('user', 'pass')
            url = httpbin('digest-auth', 'auth', 'user', 'pass', authtype)

            r = Requests().get(url, auth=auth, stream=True)
            assert r.raw_().read() != b''

            r = Requests().get(url, auth=auth, stream=False)
            assert r.raw_().read() == b''

    def test_DIGESTAUTH_WRONG_HTTP_401_GET(self, httpbin):

        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth('user', 'wrongpass')
            url = httpbin('digest-auth', 'auth', 'user', 'pass', authtype)

            r = Requests().get(url, auth=auth)
            assert r.status_code_() == 401

            r = Requests().get(url)
            assert r.status_code_() == 401

            s = Session()
            s.auth_(auth)
            r = s.get(url)
            assert r.status_code_() == 401

    def test_DIGESTAUTH_QUOTES_QOP_VALUE(self, httpbin):

        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth('user', 'pass')
            url = httpbin('digest-auth', 'auth', 'user', 'pass', authtype)

            r = Requests().get(url, auth=auth)
            assert '"auth"' in r.request_().headers_()['Authorization']

    def test_POSTBIN_GET_POST_FILES(self, httpbin):

        url = httpbin('post')
        Requests().post(url).raise_for_status()

        post1 = Requests().post(url, data={'some': 'data'})
        assert post1.status_code_() == 200

        with open('requirements-dev.txt') as f:
            post2 = Requests().post(url, files={'some': f})
        assert post2.status_code_() == 200

        post4 = Requests().post(url, data='[{"some": "json"}]')
        assert post4.status_code_() == 200

        with pytest.raises(ValueError):
            Requests().post(url, files=['bad file data'])

    def test_invalid_files_input(self, httpbin):

        url = httpbin('post')
        post = Requests().post(url,
                             files={"random-file-1": None, "random-file-2": 1})
        assert b'name="random-file-1"' not in post.request_().body_()
        assert b'name="random-file-2"' in post.request_().body_()

    def test_POSTBIN_SEEKED_OBJECT_WITH_NO_ITER(self, httpbin):

        class TestStream(object):
            def __init__(self, data):
                self.data = data.encode()
                self.length = len(self.data)
                self.index = 0

            def __len__(self):
                return self.length

            def read(self, size=None):
                if size:
                    ret = self.data[self.index:self.index + size]
                    self.index += size
                else:
                    ret = self.data[self.index:]
                    self.index = self.length
                return ret

            def tell(self):
                return self.index

            def seek(self, offset, where=0):
                if where == 0:
                    self.index = offset
                elif where == 1:
                    self.index += offset
                elif where == 2:
                    self.index = self.length + offset

        test = TestStream('test')
        post1 = Requests().post(httpbin('post'), data=test)
        assert post1.status_code_() == 200
        assert post1.json()['data'] == 'test'

        test = TestStream('test')
        test.seek(2)
        post2 = Requests().post(httpbin('post'), data=test)
        assert post2.status_code_() == 200
        assert post2.json()['data'] == 'st'

    def test_POSTBIN_GET_POST_FILES_WITH_DATA(self, httpbin):

        url = httpbin('post')
        Requests().post(url).raise_for_status()

        post1 = Requests().post(url, data={'some': 'data'})
        assert post1.status_code_() == 200

        with open('requirements-dev.txt') as f:
            post2 = Requests().post(url, data={'some': 'data'}, files={'some': f})
        assert post2.status_code_() == 200

        post4 = Requests().post(url, data='[{"some": "json"}]')
        assert post4.status_code_() == 200

        with pytest.raises(ValueError):
            Requests().post(url, files=['bad file data'])

    def test_post_with_custom_mapping(self, httpbin):
        class CustomMapping(XMutableMapping):
            def __init__(self, *args, **kwargs):
                self.data = dict(*args, **kwargs)

            def __delitem__(self, key):
                del self.data[key]

            def __getitem__(self, key):
                return self.data[key]

            def __setitem__(self, key, value):
                self.data[key] = value

            def __iter__(self):
                return iter(self.data)

            def __len__(self):
                return len(self.data)

        data = CustomMapping({'some': 'data'})
        url = httpbin('post')
        found_json = Requests().post(url, data=data).json().get('form')
        assert found_json == {'some': 'data'}

    def test_conflicting_post_params(self, httpbin):
        url = httpbin('post')
        with open('requirements-dev.txt') as f:
            with pytest.raises(ValueError):
                Requests().post(url, data='[{"some": "data"}]', files={'some': f})
            with pytest.raises(ValueError):
                Requests().post(url, data=u('[{"some": "data"}]'), files={'some': f})

    def test_request_ok_set(self, httpbin):
        r = Requests().get(httpbin('status', '404'))
        assert not r.ok()

    def test_status_raising(self, httpbin):
        r = Requests().get(httpbin('status', '404'))
        with pytest.raises(exceptions.HTTPError):
            r.raise_for_status()

        r = Requests().get(httpbin('status', '500'))
        assert not r.ok()

    def test_decompress_gzip(self, httpbin):
        r = Requests().get(httpbin('gzip'))
        r.content_().decode('ascii')

    @pytest.mark.parametrize(
        'url, params', (
            ('/get', {'foo': 'føø'}),
            ('/get', {'føø': 'føø'}),
            ('/get', {'føø': 'føø'}),
            ('/get', {'foo': 'foo'}),
            ('ø', {'foo': 'foo'}),
        ))
    def test_unicode_get(self, httpbin, url, params):
        Requests().get(httpbin(url), params=params)

    def test_unicode_header_name(self, httpbin):
        Requests().put(
            httpbin('put'),
            headers={XCompat().str('Content-Type'): 'application/octet-stream'},
            data='\xff')  # XCompat().str is unicode.

    def test_pyopenssl_redirect(self, httpbin_secure, httpbin_ca_bundle):
        Requests().get(httpbin_secure('status', '301'), verify=httpbin_ca_bundle)

    def test_invalid_ca_certificate_path(self, httpbin_secure):
        INVALID_PATH = '/garbage'
        with pytest.raises(IOError) as e:
            Requests().get(httpbin_secure(), verify=INVALID_PATH)
        assert XCompat().str(e.value) == 'Could not find a suitable TLS CA certificate bundle, invalid path: {}'.format(INVALID_PATH)

    def test_invalid_ssl_certificate_files(self, httpbin_secure):
        INVALID_PATH = '/garbage'
        with pytest.raises(IOError) as e:
            Requests().get(httpbin_secure(), cert=INVALID_PATH)
        assert XCompat().str(e.value) == 'Could not find the TLS certificate file, invalid path: {}'.format(INVALID_PATH)

        with pytest.raises(IOError) as e:
            Requests().get(httpbin_secure(), cert=('.', INVALID_PATH))
        assert XCompat().str(e.value) == 'Could not find the TLS key file, invalid path: {}'.format(INVALID_PATH)

    def test_http_with_certificate(self, httpbin):
        r = Requests().get(httpbin(), cert='.')
        assert r.status_code_() == 200

    def test_https_warnings(self, nosan_server):
        """warnings are emitted with Requests().put(get"""
        host, port, ca_bundle = nosan_server
        if HAS_MODERN_SSL or HAS_PYOPENSSL:
            warnings_expected = ('SubjectAltNameWarning', )
        else:
            warnings_expected = ('SNIMissingWarning',
                                 'InsecurePlatformWarning',
                                 'SubjectAltNameWarning', )

        with pytest.warns(None) as warning_records:
            warnings.simplefilter('always')
            Requests().get("https://localhost:{}/".format(port), verify=ca_bundle)

        warning_records = [item for item in warning_records
                           if item.category.__name__ != 'ResourceWarning']

        warnings_category = tuple(
            item.category.__name__ for item in warning_records)
        assert warnings_category == warnings_expected

    def test_certificate_failure(self, httpbin_secure):
        """
        When underlying SSL problems occur, an exceptions.SSLError is raised.
        """
        with pytest.raises(exceptions.SSLError):
            # Our local httpbin does not have a trusted CA, so this call will
            # fail if we use our default trust bundle.
            Requests().get(httpbin_secure('status', '200'))

    def test_urlencoded_get_query_multivalued_param(self, httpbin):

        r = Requests().get(httpbin('get'), params={'test': ['foo', 'baz']})
        assert r.status_code_() == 200
        assert r.url_() == httpbin('get?test=foo&test=baz')

    def test_form_encoded_post_query_multivalued_element(self, httpbin):
        prep = Request().method_('POST').url_(httpbin('post')).data_(dict(test=['foo', 'baz'])).prepare()
        assert prep.body_() == 'test=foo&test=baz'

    def test_different_encodings_dont_break_post(self, httpbin):
        r = Requests().post(httpbin('post'),
            data={'stuff': json.dumps({'a': 123})},
            params={'blah': 'asdf1234'},
            files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code_() == 200

    @pytest.mark.parametrize(
        'data', (
            {'stuff': u('ëlïxr')},
            {'stuff': u('ëlïxr').encode('utf-8')},
            {'stuff': 'elixr'},
            {'stuff': 'elixr'.encode('utf-8')},
        ))
    def test_unicode_multipart_post(self, httpbin, data):
        r = Requests().post(httpbin('post'),
            data=data,
            files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code_() == 200

    def test_unicode_multipart_post_fieldnames(self, httpbin):
        filename = XOs().path().splitext(__file__)[0] + '.py'
        prep = Request().method_('POST').url_(httpbin('post'))\
            .data_({'stuff'.encode('utf-8'): 'elixr'})\
            .files_({'file': ('test_requests.py', open(filename, 'rb'))})\
            .prepare()
        assert b'name="stuff"' in prep.body_()
        assert b'name="b\'stuff\'"' not in prep.body_()

    def test_unicode_method_name(self, httpbin):
        files = {'file': open(__file__, 'rb')}
        r = Requests().request(
            method=u('POST'), url=httpbin('post'), files=files)
        assert r.status_code_() == 200

    def test_unicode_method_name_with_request_object(self, httpbin):
        s = Session()
        req = Request().method_(u('POST')).url_(httpbin('post')).files_({'file': open(__file__, 'rb')})
        prep = s.prepare_request(req)
        assert XCompat().is_builtin_str_instance(prep.method_())
        assert prep.method_() == 'POST'

        resp = s.send(prep)
        assert resp.status_code_() == 200

    def test_non_prepared_request_error(self):
        s = Session()
        req = Request().method_(u('POST')).url_('/')

        with pytest.raises(ValueError) as e:
            s.send(req)
        assert XCompat().str(e.value) == 'You can only send PreparedRequests.'

    def test_custom_content_type(self, httpbin):
        r = Requests().post(
            httpbin('post'),
            data={'stuff': json.dumps({'a': 123})},
            files={
                'file1': ('test_requests.py', open(__file__, 'rb')),
                'file2': ('test_requests', open(__file__, 'rb'),
                    'text/py-content-type')})
        assert r.status_code_() == 200
        assert b"text/py-content-type" in r.request_().body_()

    def test_hook_receives_request_arguments(self, httpbin):
        def hook(resp, **kwargs):
            assert resp is not None
            assert kwargs != {}

        s = Session()
        r = Request().method_('GET').url_(httpbin()).hooks_({'response': hook})
        prep = s.prepare_request(r)
        s.send(prep)

    def test_session_hooks_are_used_with_no_request_hooks(self, httpbin):
        hook = lambda x, *args, **kwargs: x
        s = Session()
        s.hooks_()['response'].append(hook)
        r = Request().method_('GET').url_(httpbin())
        prep = s.prepare_request(r)
        assert prep.hooks_()['response'] != []
        assert prep.hooks_()['response'] == [hook]

    def test_session_hooks_are_overridden_by_request_hooks(self, httpbin):
        hook1 = lambda x, *args, **kwargs: x
        hook2 = lambda x, *args, **kwargs: x
        assert hook1 is not hook2
        s = Session()
        s.hooks_()['response'].append(hook2)
        r = Request().method_('GET').url_(httpbin()).hooks_({'response': [hook1]})
        prep = s.prepare_request(r)
        assert prep.hooks_()['response'] == [hook1]

    def test_prepared_request_hook(self, httpbin):
        def hook(resp, **kwargs):
            resp.hook_working = True
            return resp

        req = Request().method_('GET').url_(httpbin()).hooks_({'response': hook})
        prep = req.prepare()

        s = Session()
        s.proxies_(XCompat().getproxies())
        resp = s.send(prep)

        assert hasattr(resp, 'hook_working')

    def test_prepared_from_session(self, httpbin):
        class DummyAuth(AuthBase):
            def __call__(self, r):
                r.headers_()['Dummy-Auth-Test'] = 'dummy-auth-test-ok'
                return r

        req = Request().method_('GET').url_(httpbin('headers'))
        assert not req.auth_()

        s = Session()
        s.auth_(DummyAuth())

        prep = s.prepare_request(req)
        resp = s.send(prep)

        assert resp.json()['headers'][
            'Dummy-Auth-Test'] == 'dummy-auth-test-ok'

    def test_prepare_request_with_bytestring_url(self):
        req = Request().method_('GET').url_(b'https://httpbin.org/')
        s = Session()
        prep = s.prepare_request(req)
        assert prep.url_() == "https://httpbin.org/"

    def test_request_with_bytestring_host(self, httpbin):
        s = Session()
        resp = s.request(
            'GET',
            httpbin('cookies/set?cookie=value'),
            allow_redirects=False,
            headers={'Host': b'httpbin.org'}
        )
        assert resp.cookies_().get('cookie') == 'value'

    def test_links(self):
        r = Response()
        r.headers_({
            'cache-control': 'public, max-age=60, s-maxage=60',
            'connection': 'keep-alive',
            'content-encoding': 'gzip',
            'content-type': 'application/json; charset=utf-8',
            'date': 'Sat, 26 Jan 2013 16:47:56 GMT',
            'etag': '"6ff6a73c0e446c1f61614769e3ceb778"',
            'last-modified': 'Sat, 26 Jan 2013 16:22:39 GMT',
            'link': ('<https://api.github.com/users/kennethreitz/repos?'
                     'page=2&per_page=10>; rel="next", <https://api.github.'
                     'com/users/kennethreitz/repos?page=7&per_page=10>; '
                     ' rel="last"'),
            'server': 'GitHub.com',
            'status': '200 OK',
            'vary': 'Accept',
            'x-content-type-options': 'nosniff',
            'x-github-media-type': 'github.beta',
            'x-ratelimit-limit': '60',
            'x-ratelimit-remaining': '57'
        })
        assert r.links['next']['rel'] == 'next'

    def test_cookie_parameters(self):
        key = 'some_cookie'
        value = 'some_value'
        secure = True
        domain = 'test.com'
        rest = {'HttpOnly': True}

        jar = CookieJar()
        jar.set(key, value, secure=secure, domain=domain, rest=rest)

        assert len(jar) == 1
        assert 'some_cookie' in jar

        cookie = list(jar)[0]
        assert cookie.secure == secure
        assert cookie.domain == domain
        assert cookie._rest['HttpOnly'] == rest['HttpOnly']

    def test_cookie_as_dict_keeps_len(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = CookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())

        assert len(jar) == 2
        assert len(d1) == 2
        assert len(d2) == 2
        assert len(d3) == 2

    def test_cookie_as_dict_keeps_items(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = CookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())

        assert d1['some_cookie'] == 'some_value'
        assert d2['some_cookie'] == 'some_value'
        assert d3['some_cookie1'] == 'some_value1'

    def test_cookie_as_dict_keys(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = CookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        keys = jar.keys()
        assert keys == list(keys)
        # make sure one can use keys multiple times
        assert list(keys) == list(keys)

    def test_cookie_as_dict_values(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = CookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        values = jar.values()
        assert values == list(values)
        # make sure one can use values multiple times
        assert list(values) == list(values)

    def test_cookie_as_dict_items(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = CookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        items = jar.items()
        assert items == list(items)
        # make sure one can use items multiple times
        assert list(items) == list(items)

    def test_cookie_duplicate_names_different_domains(self):
        key = 'some_cookie'
        value = 'some_value'
        domain1 = 'test1.com'
        domain2 = 'test2.com'

        jar = CookieJar()
        jar.set(key, value, domain=domain1)
        jar.set(key, value, domain=domain2)
        assert key in jar
        items = jar.items()
        assert len(items) == 2

        # Verify that CookieConflictError is raised if domain is not specified
        with pytest.raises(CookieConflictError):
            jar.get(key)

        # Verify that CookieConflictError is not raised if domain is specified
        cookie = jar.get(key, domain=domain1)
        assert cookie == value

    def test_cookie_duplicate_names_raises_cookie_conflict_error(self):
        key = 'some_cookie'
        value = 'some_value'
        path = 'some_path'

        jar = CookieJar()
        jar.set(key, value, path=path)
        jar.set(key, value)
        with pytest.raises(CookieConflictError):
            jar.get(key)

    def test_cookie_policy_copy(self):
        class MyCookiePolicy(XDefaultCookiePolicy):
            pass

        jar = CookieJar()
        jar.set_policy(MyCookiePolicy())
        assert isinstance(jar.copy().get_policy(), MyCookiePolicy)

    def test_time_elapsed_blank(self, httpbin):
        r = Requests().get(httpbin('get'))
        td = r.elapsed_()
        total_seconds = ((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6)
        assert total_seconds > 0.0

    def test_empty_response_has_content_none(self):
        r = Response()
        assert r.content_() is None

    def test_response_is_iterable(self):
        r = Response()
        io = CompatStringIO.StringIO('abc')
        read_ = io.read

        def read_mock(amt, decode_content=None):
            return read_(amt)
        setattr(io, 'read', read_mock)
        r.raw_(io)
        assert next(iter(r))
        io.close()

    def test_response_decode_unicode(self):
        """When called with decode_unicode, Response.iter_content should always
        return unicode.
        """
        r = Response()
        r.contentClass._content_consumed = True
        r.contentClass._content = b'the content'
        r.encoding_('ascii')

        chunks = r.iter_content(decode_unicode=True)
        assert all(XCompat().is_str_instance(chunk) for chunk in chunks)

        # also for streaming
        r = Response()
        r.raw_(io.BytesIO(b'the content'))
        r.encoding_('ascii')
        chunks = r.iter_content(decode_unicode=True)
        assert all(XCompat().is_str_instance(chunk) for chunk in chunks)

    def test_response_reason_unicode(self):
        # check for unicode HTTP status
        r = Response()
        r.url_(u'unicode URL')
        r.reason_(u'Komponenttia ei löydy'.encode('utf-8'))
        r.status_code_(404)
        r.encoding_(None)
        assert not r.ok()  # old behaviour - crashes here

    def test_response_reason_unicode_fallback(self):
        # check raise_status falls back to ISO-8859-1
        r = Response()
        r.url_('some url')
        reason = u'Komponenttia ei löydy'
        r.reason_(reason.encode('latin-1'))
        r.status_code_(500)
        r.encoding_(None)
        with pytest.raises(exceptions.HTTPError) as e:
            r.raise_for_status()
        assert reason in e.value.args[0]

    def test_response_chunk_size_type(self):
        """Ensure that chunk_size is passed as None or an integer, otherwise
        raise a TypeError.
        """
        r = Response()
        r.raw_(io.BytesIO(b'the content'))
        chunks = r.iter_content(1)
        assert all(len(chunk) == 1 for chunk in chunks)

        r = Response()
        r.raw_(io.BytesIO(b'the content'))
        chunks = r.iter_content(None)
        assert list(chunks) == [b'the content']

        r = Response()
        r.raw_(io.BytesIO(b'the content'))
        with pytest.raises(TypeError):
            chunks = r.iter_content("1024")

    def test_request_and_response_are_pickleable(self, httpbin):
        r = Requests().get(httpbin('get'))

        # verify we can pickle the original request
        assert pickle.loads(pickle.dumps(r.request_()))

        # verify we can pickle the response and that we have access to
        # the original request.
        pr = pickle.loads(pickle.dumps(r))
        assert r.request_().url_() == pr.request_().url_()
        assert r.request_().headers_() == pr.request_().headers_()

    def test_prepared_request_is_pickleable(self, httpbin):
        p = Request().method_('GET').url_(httpbin('get')).prepare()

        # Verify PreparedRequest can be pickled and unpickled
        r = pickle.loads(pickle.dumps(p))
        assert r.url_() == p.url_()
        assert r.headers_() == p.headers_()
        assert r.body_() == p.body_()

        # Verify unpickled PreparedRequest sends properly
        s = Session()
        resp = s.send(r)
        assert resp.status_code_() == 200

    def test_prepared_request_with_file_is_pickleable(self, httpbin):
        files = {'file': open(__file__, 'rb')}
        r = Request().method_('POST').url_(httpbin('post')).files_(files)
        p = r.prepare()

        # Verify PreparedRequest can be pickled and unpickled
        r = pickle.loads(pickle.dumps(p))
        assert r.url_() == p.url_()
        assert r.headers_() == p.headers_()
        assert r.body_() == p.body_()

        # Verify unpickled PreparedRequest sends properly
        s = Session()
        resp = s.send(r)
        assert resp.status_code_() == 200

    def test_prepared_request_with_hook_is_pickleable(self, httpbin):
        r = Request().method_('GET').url_(httpbin('get')).hooks_(Hooks().default_hooks())
        p = r.prepare()

        # Verify PreparedRequest can be pickled
        r = pickle.loads(pickle.dumps(p))
        assert r.url_() == p.url_()
        assert r.headers_() == p.headers_()
        assert r.body_() == p.body_()
        assert r.hooks_() == p.hooks_()

        # Verify unpickled PreparedRequest sends properly
        s = Session()
        resp = s.send(r)
        assert resp.status_code_() == 200

    def test_cannot_send_unprepared_requests(self, httpbin):
        r = Request().url_(httpbin())
        with pytest.raises(ValueError):
            Session().send(r)

    def test_http_error(self):
        error = exceptions.HTTPError()
        assert not error.response
        response = Response()
        error = exceptions.HTTPError(response=response)
        assert error.response == response
        error = exceptions.HTTPError('message', response=response)
        assert XCompat().str(error) == 'message'
        assert error.response == response

    def test_session_pickling(self, httpbin):
        r = Request().method_('GET').url_(httpbin('get'))
        s = Session()

        s = pickle.loads(pickle.dumps(s))
        s.proxies_(XCompat().getproxies())

        r = s.send(r.prepare())
        assert r.status_code_() == 200

    def test_fixes_1329(self, httpbin):
        """Ensure that header updates are done case-insensitively."""
        s = Session()
        s.headers_().update({'ACCEPT': 'BOGUS'})
        s.headers_().update({'accept': 'application/json'})
        r = s.get(httpbin('get'))
        headers = r.request_().headers_()
        assert headers['accept'] == 'application/json'
        assert headers['Accept'] == 'application/json'
        assert headers['ACCEPT'] == 'application/json'

    def test_uppercase_scheme_redirect(self, httpbin):
        parts = XCompat().urlparse(httpbin('html'))
        url = "HTTP://" + parts.netloc + parts.path
        r = Requests().get(httpbin('redirect-to'), params={'url': url})
        assert r.status_code_() == 200
        assert r.url_().lower() == url.lower()

    def test_transport_adapter_ordering(self):
        s = Session()
        order = ['https://', 'http://']
        assert order == list(s.adapters)
        s.mount('http://git', HTTPAdapter())
        s.mount('http://github', HTTPAdapter())
        s.mount('http://github.com', HTTPAdapter())
        s.mount('http://github.com/about/', HTTPAdapter())
        order = [
            'http://github.com/about/',
            'http://github.com',
            'http://github',
            'http://git',
            'https://',
            'http://',
        ]
        assert order == list(s.adapters)
        s.mount('http://gittip', HTTPAdapter())
        s.mount('http://gittip.com', HTTPAdapter())
        s.mount('http://gittip.com/about/', HTTPAdapter())
        order = [
            'http://github.com/about/',
            'http://gittip.com/about/',
            'http://github.com',
            'http://gittip.com',
            'http://github',
            'http://gittip',
            'http://git',
            'https://',
            'http://',
        ]
        assert order == list(s.adapters)
        s2 = Session()
        s2.adapters = {'http://': HTTPAdapter()}
        s2.mount('https://', HTTPAdapter())
        assert 'http://' in s2.adapters
        assert 'https://' in s2.adapters

    def test_session_get_adapter_prefix_matching(self):
        prefix = 'https://example.com'
        more_specific_prefix = prefix + '/some/path'

        url_matching_only_prefix = prefix + '/another/path'
        url_matching_more_specific_prefix = more_specific_prefix + '/longer/path'
        url_not_matching_prefix = 'https://another.example.com/'

        s = Session()
        prefix_adapter = HTTPAdapter()
        more_specific_prefix_adapter = HTTPAdapter()
        s.mount(prefix, prefix_adapter)
        s.mount(more_specific_prefix, more_specific_prefix_adapter)

        assert s.get_adapter(url_matching_only_prefix) is prefix_adapter
        assert s.get_adapter(url_matching_more_specific_prefix) is more_specific_prefix_adapter
        assert s.get_adapter(url_not_matching_prefix) not in (prefix_adapter, more_specific_prefix_adapter)

    def test_session_get_adapter_prefix_matching_mixed_case(self):
        mixed_case_prefix = 'hTtPs://eXamPle.CoM/MixEd_CAse_PREfix'
        url_matching_prefix = mixed_case_prefix + '/full_url'

        s = Session()
        my_adapter = HTTPAdapter()
        s.mount(mixed_case_prefix, my_adapter)

        assert s.get_adapter(url_matching_prefix) is my_adapter

    def test_session_get_adapter_prefix_matching_is_case_insensitive(self):
        mixed_case_prefix = 'hTtPs://eXamPle.CoM/MixEd_CAse_PREfix'
        url_matching_prefix_with_different_case = 'HtTpS://exaMPLe.cOm/MiXeD_caSE_preFIX/another_url'

        s = Session()
        my_adapter = HTTPAdapter()
        s.mount(mixed_case_prefix, my_adapter)

        assert s.get_adapter(url_matching_prefix_with_different_case) is my_adapter

    def test_header_remove_is_case_insensitive(self, httpbin):
        # From issue #1321
        s = Session()
        s.headers_()['foo'] = 'bar'
        r = s.get(httpbin('get'), headers={'FOO': None})
        assert 'foo' not in r.request_().headers_()

    def test_params_are_merged_case_sensitive(self, httpbin):
        s = Session()
        s.params_()['foo'] = 'bar'
        r = s.get(httpbin('get'), params={'FOO': 'bar'})
        assert r.json()['args'] == {'foo': 'bar', 'FOO': 'bar'}

    def test_long_authinfo_in_url(self):
        url = 'http://{}:{}@{}:9000/path?query#frag'.format(
            'E8A3BE87-9E3F-4620-8858-95478E385B5B',
            'EA770032-DA4D-4D84-8CE9-29C6D910BF1E',
            'exactly-------------sixty-----------three------------characters',
        )
        r = Request().method_('GET').url_(url).prepare()
        assert r.url_() == url

    def test_header_keys_are_native(self, httpbin):
        headers = {u('unicode'): 'blah', 'byte'.encode('ascii'): 'blah'}
        p = Request().method_('GET').url_(httpbin('get')).headers_(headers).prepare()

        # This is testing that they are builtin strings. A bit weird, but there
        # we go.
        assert 'unicode' in p.headers_().keys()
        assert 'byte' in p.headers_().keys()

    def test_header_validation(self, httpbin):
        """Ensure prepare_headers regex isn't flagging valid header contents."""
        headers_ok = {'foo': 'bar baz qux',
                      'bar': u'fbbq'.encode('utf8'),
                      'baz': '',
                      'qux': '1'}
        r = Requests().get(httpbin('get'), headers = headers_ok)
        assert r.request_().headers_()['foo'] == headers_ok['foo']

    def test_header_value_not_str(self, httpbin):
        """Ensure the header value is of type string or bytes as
        per discussion in GH issue #3386
        """
        headers_int = {'foo': 3}
        headers_dict = {'bar': {'foo': 'bar'}}
        headers_list = {'baz': ['foo', 'bar']}

        # Test for int
        with pytest.raises(exceptions.InvalidHeader) as excinfo:
            r = Requests().get(httpbin('get'), headers=headers_int)
        assert 'foo' in XCompat().str(excinfo.value)
        # Test for dict
        with pytest.raises(exceptions.InvalidHeader) as excinfo:
            r = Requests().get(httpbin('get'), headers=headers_dict)
        assert 'bar' in XCompat().str(excinfo.value)
        # Test for list
        with pytest.raises(exceptions.InvalidHeader) as excinfo:
            r = Requests().get(httpbin('get'), headers=headers_list)
        assert 'baz' in XCompat().str(excinfo.value)

    def test_header_no_return_chars(self, httpbin):
        """Ensure that a header containing return character sequences raise an
        exception. Otherwise, multiple headers are created from single string.
        """
        headers_ret = {'foo': 'bar\r\nbaz: qux'}
        headers_lf = {'foo': 'bar\nbaz: qux'}
        headers_cr = {'foo': 'bar\rbaz: qux'}

        # Test for newline
        with pytest.raises(exceptions.InvalidHeader):
            r = Requests().get(httpbin('get'), headers=headers_ret)
        # Test for line feed
        with pytest.raises(exceptions.InvalidHeader):
            r = Requests().get(httpbin('get'), headers=headers_lf)
        # Test for carriage return
        with pytest.raises(exceptions.InvalidHeader):
            r = Requests().get(httpbin('get'), headers=headers_cr)

    def test_header_no_leading_space(self, httpbin):
        """Ensure headers containing leading whitespace raise
        exceptions.InvalidHeader Error before sending.
        """
        headers_space = {'foo': ' bar'}
        headers_tab = {'foo': '   bar'}

        # Test for whitespace
        with pytest.raises(exceptions.InvalidHeader):
            r = Requests().get(httpbin('get'), headers=headers_space)
        # Test for tab
        with pytest.raises(exceptions.InvalidHeader):
            r = Requests().get(httpbin('get'), headers=headers_tab)

    @pytest.mark.parametrize('files', ('foo', b'foo', bytearray(b'foo')))
    def test_can_send_objects_with_files(self, httpbin, files):
        r = Request().method_('POST').url_(httpbin('post')).data_({'a': 'this is a string'}).files_({'b': files})
        p = r.prepare()
        assert 'multipart/form-data' in p.headers_()['Content-Type']

    def test_can_send_file_object_with_non_string_filename(self, httpbin):
        f = io.BytesIO()
        f.name = 2
        p = Request().method_('POST').url_(httpbin('post')).files_({'f': f}).prepare()

        assert 'multipart/form-data' in p.headers_()['Content-Type']

    def test_autoset_header_values_are_native(self, httpbin):
        data = 'this is a string'
        length = '16'
        req = Request().method_('POST').url_(httpbin('post')).data_(data)
        p = req.prepare()

        assert p.headers_()['Content-Length'] == length

    def test_nonhttp_schemes_dont_check_URLs(self):
        test_urls = (
            'data:image/gif;base64,R0lGODlhAQABAHAAACH5BAUAAAAALAAAAAABAAEAAAICRAEAOw==',
            'file:///etc/passwd',
            'magnet:?xt=urn:btih:be08f00302bc2d1d3cfa3af02024fa647a271431',
        )
        for test_url in test_urls:
            req = Request().method_('GET').url_(test_url)
            preq = req.prepare()
            assert test_url == preq.url_()

    def test_auth_is_stripped_on_http_downgrade(self, httpbin, httpbin_secure, httpbin_ca_bundle):
        r = Requests().get(
            httpbin_secure('redirect-to'),
            params={'url': httpbin('get')},
            auth=('user', 'pass'),
            verify=httpbin_ca_bundle
        )
        assert r.history_()[0].request_().headers_()['Authorization']
        assert 'Authorization' not in r.request_().headers_()

    def test_auth_is_retained_for_redirect_on_host(self, httpbin):
        r = Requests().get(httpbin('redirect/1'), auth=('user', 'pass'))
        h1 = r.history_()[0].request_().headers_()['Authorization']
        h2 = r.request_().headers_()['Authorization']

        assert h1 == h2

    def test_should_strip_auth_host_change(self):
        s = Session()
        assert s.should_strip_auth('http://example.com/foo', 'http://another.example.com/')

    def test_should_strip_auth_http_downgrade(self):
        s = Session()
        assert s.should_strip_auth('https://example.com/foo', 'http://example.com/bar')

    def test_should_strip_auth_https_upgrade(self):
        s = Session()
        assert not s.should_strip_auth('http://example.com/foo', 'https://example.com/bar')
        assert not s.should_strip_auth('http://example.com:80/foo', 'https://example.com/bar')
        assert not s.should_strip_auth('http://example.com/foo', 'https://example.com:443/bar')
        # Non-standard ports should trigger stripping
        assert s.should_strip_auth('http://example.com:8080/foo', 'https://example.com/bar')
        assert s.should_strip_auth('http://example.com/foo', 'https://example.com:8443/bar')

    def test_should_strip_auth_port_change(self):
        s = Session()
        assert s.should_strip_auth('http://example.com:1234/foo', 'https://example.com:4321/bar')

    @pytest.mark.parametrize(
        'old_uri, new_uri', (
            ('https://example.com:443/foo', 'https://example.com/bar'),
            ('http://example.com:80/foo', 'http://example.com/bar'),
            ('https://example.com/foo', 'https://example.com:443/bar'),
            ('http://example.com/foo', 'http://example.com:80/bar')
        ))
    def test_should_strip_auth_default_port(self, old_uri, new_uri):
        s = Session()
        assert not s.should_strip_auth(old_uri, new_uri)

    def test_manual_redirect_with_partial_body_read(self, httpbin):
        s = Session()
        r1 = s.get(httpbin('redirect/2'), allow_redirects=False, stream=True)
        assert r1.is_redirect()
        rg = s.resolve_redirects(r1, r1.request_(), stream=True)

        # read only the first eight bytes of the response body,
        # then follow the redirect
        r1.iter_content(8)
        r2 = next(rg)
        assert r2.is_redirect()

        # read all of the response via iter_content,
        # then follow the redirect
        for _ in r2.iter_content():
            pass
        r3 = next(rg)
        assert not r3.is_redirect()

    def test_prepare_body_position_non_stream(self):
        prep = Request().method_('GET').url_('http://example.com').data_(b'the data').prepare()
        assert prep._body_position is None

    def test_rewind_body(self):
        data = io.BytesIO(b'the data')
        prep = Request().method_('GET').url_('http://example.com').data_(data).prepare()
        assert prep._body_position == 0
        assert prep.body_().read() == b'the data'

        # the data has all been read
        assert prep.body_().read() == b''

        # rewind it back
        Utils().rewind_body(prep)
        assert prep.body_().read() == b'the data'

    def test_rewind_partially_read_body(self):
        data = io.BytesIO(b'the data')
        data.read(4)  # read some data
        prep = Request().method_('GET').url_('http://example.com').data_(data).prepare()
        assert prep._body_position == 4
        assert prep.body_().read() == b'data'

        # the data has all been read
        assert prep.body_().read() == b''

        # rewind it back
        Utils().rewind_body(prep)
        assert prep.body_().read() == b'data'

    def test_rewind_body_no_seek(self):
        class BadFileObj:
            def __init__(self, data):
                self.data = data

            def tell(self):
                return 0

            def __iter__(self):
                return

        data = BadFileObj('the data')
        prep = Request().method_('GET').url_('http://example.com').data_(data).prepare()
        assert prep._body_position == 0

        with pytest.raises(exceptions.UnrewindableBodyError) as e:
            Utils().rewind_body(prep)

        assert 'Unable to rewind request body' in XCompat().str(e)

    def test_rewind_body_failed_seek(self):
        class BadFileObj:
            def __init__(self, data):
                self.data = data

            def tell(self):
                return 0

            def seek(self, pos, whence=0):
                raise OSError()

            def __iter__(self):
                return

        data = BadFileObj('the data')
        prep = Request().method_('GET').url_('http://example.com').data_(data).prepare()
        assert prep._body_position == 0

        with pytest.raises(exceptions.UnrewindableBodyError) as e:
            Utils().rewind_body(prep)

        assert 'error occurred when rewinding request body' in XCompat().str(e)

    def test_rewind_body_failed_tell(self):
        class BadFileObj:
            def __init__(self, data):
                self.data = data

            def tell(self):
                raise OSError()

            def __iter__(self):
                return

        data = BadFileObj('the data')
        prep = Request().method_('GET').url_('http://example.com').data_(data).prepare()
        assert prep._body_position is not None

        with pytest.raises(exceptions.UnrewindableBodyError) as e:
            Utils().rewind_body(prep)

        assert 'Unable to rewind request body' in XCompat().str(e)

    def _patch_adapter_gzipped_redirect(self, session, url):
        adapter = session.get_adapter(url=url)
        org_build_response = adapter.build_response
        self._patched_response = False

        def build_response(*args, **kwargs):
            resp = org_build_response(*args, **kwargs)
            if not self._patched_response:
                resp.raw_().headers['content-encoding'] = 'gzip'
                self._patched_response = True
            return resp

        adapter.build_response = build_response

    def test_redirect_with_wrong_gzipped_header(self, httpbin):
        s = Session()
        url = httpbin('redirect/1')
        self._patch_adapter_gzipped_redirect(s, url)
        s.get(url)

    @pytest.mark.parametrize(
        'username, password, auth_str', (
            ('test', 'test', 'Basic dGVzdDp0ZXN0'),
            (u'имя'.encode('utf-8'), u'пароль'.encode('utf-8'), 'Basic 0LjQvNGPOtC/0LDRgNC+0LvRjA=='),
        ))
    def test_basic_auth_str_is_always_native(self, username, password, auth_str):
        s = Auth().basic_auth_str(username, password)
        assert XCompat().is_builtin_str_instance(s)
        assert s == auth_str

    def test_requests_history_is_saved(self, httpbin):
        r = Requests().get(httpbin('redirect/5'))
        total = r.history_()[-1].history_()
        i = 0
        for item in r.history_():
            assert item.history_() == total[0:i]
            i += 1

    def test_json_param_post_content_type_works(self, httpbin):
        r = Requests().post(
            httpbin('post'),
            json={'life': 42}
        )
        assert r.status_code_() == 200
        assert 'application/json' in r.request_().headers_()['Content-Type']
        assert {'life': 42} == r.json()['json']

    def test_json_param_post_should_not_override_data_param(self, httpbin):
        prep = Request().method_('POST').url_(httpbin('post'))\
            .data_({'stuff': 'elixr'}).json_({'music': 'flute'}).prepare()
        assert 'stuff=elixr' == prep.body_()

    def test_response_iter_lines(self, httpbin):
        r = Requests().get(httpbin('stream/4'), stream=True)
        assert r.status_code_() == 200

        it = r.iter_lines()
        next(it)
        assert len(list(it)) == 3

    def test_response_context_manager(self, httpbin):
        with Requests().get(httpbin('stream/4'), stream=True) as response:
            assert isinstance(response, Response)

        assert response.raw_().closed

    def test_unconsumed_session_response_closes_connection(self, httpbin):
        s = Session()

        with contextlib.closing(s.get(httpbin('stream/4'), stream=True)) as response:
            pass

        assert response.contentClass._content_consumed is False
        assert response.raw_().closed

    @pytest.mark.xfail
    def test_response_iter_lines_reentrant(self, httpbin):
        """Response.iter_lines() is not reentrant safe"""
        r = Requests().get(httpbin('stream/4'), stream=True)
        assert r.status_code_() == 200

        next(r.iter_lines())
        assert len(list(r.iter_lines())) == 3

    def test_session_close_proxy_clear(self, mocker):
        proxies = {
          'one': mocker.Mock(),
          'two': mocker.Mock(),
        }
        session = Session()
        mocker.patch.dict(session.adapters['http://'].proxy_manager, proxies)
        session.close()
        proxies['one'].clear.assert_called_once_with()
        proxies['two'].clear.assert_called_once_with()

    def test_proxy_auth(self):
        adapter = HTTPAdapter()
        headers = adapter.proxy_headers("http://user:pass@httpbin.org")
        assert headers == {'Proxy-Authorization': 'Basic dXNlcjpwYXNz'}

    def test_proxy_auth_empty_pass(self):
        adapter = HTTPAdapter()
        headers = adapter.proxy_headers("http://user:@httpbin.org")
        assert headers == {'Proxy-Authorization': 'Basic dXNlcjo='}

    def test_response_json_when_content_is_None(self, httpbin):
        r = Requests().get(httpbin('/status/204'))
        # Make sure r.content is None
        r.status_code_(0)
        r.contentClass._content = False
        r.contentClass._content_consumed = False

        assert r.content_() is None
        with pytest.raises(ValueError):
            r.json()

    def test_response_without_release_conn(self):
        """Test `close` call for non-urllib3-like raw objects.
        Should work when `release_conn` attr doesn't exist on `response.raw`.
        """
        resp = Response()
        resp.raw_(CompatStringIO.StringIO('test'))
        assert not resp.raw_().closed
        resp.close()
        assert resp.raw_().closed

    def test_empty_stream_with_auth_does_not_set_content_length_header(self, httpbin):
        """Ensure that a byte stream with size 0 will not set both a Content-Length
        and Transfer-Encoding header.
        """
        file_obj = io.BytesIO(b'')
        prep = Request().method_('POST').url_(httpbin('post')).auth_(('user', 'pass')).data_(file_obj).prepare()
        assert 'Transfer-Encoding' in prep.headers_()
        assert 'Content-Length' not in prep.headers_()

    def test_stream_with_auth_does_not_set_transfer_encoding_header(self, httpbin):
        """Ensure that a byte stream with size > 0 will not set both a Content-Length
        and Transfer-Encoding header.
        """
        file_obj = io.BytesIO(b'test data')
        prep = Request().method_('POST').url_(httpbin('post')).auth_(('user', 'pass')).data_(file_obj).prepare()
        assert 'Transfer-Encoding' not in prep.headers_()
        assert 'Content-Length' in prep.headers_()

    def test_chunked_upload_does_not_set_content_length_header(self, httpbin):
        """Ensure that requests with a generator body stream using
        Transfer-Encoding: chunked, not a Content-Length header.
        """
        data = (i for i in [b'a', b'b', b'c'])
        prep = Request().method_('POST').url_(httpbin('post')).data_(data).prepare()
        assert 'Transfer-Encoding' in prep.headers_()
        assert 'Content-Length' not in prep.headers_()

    def test_custom_redirect_mixin(self, httpbin):
        """Tests a custom mixin to overwrite ``get_redirect_target``.

        Ensures a subclassed ``Session`` can handle a certain type of
        malformed redirect responses.

        1. original request receives a proper response: 302 redirect
        2. following the redirect, a malformed response is given:
            status code = HTTP 200
            location = alternate url
        3. the custom session catches the edge case and follows the redirect
        """
        url_final = httpbin('html')
        querystring_malformed = XCompat().urlencode({'location': url_final})
        url_redirect_malformed = httpbin('response-headers?%s' % querystring_malformed)
        querystring_redirect = XCompat().urlencode({'url': url_redirect_malformed})
        url_redirect = httpbin('redirect-to?%s' % querystring_redirect)
        urls_test = [url_redirect,
                     url_redirect_malformed,
                     url_final,
                     ]

        class CustomRedirectSession(Session):
            def get_redirect_target(self, resp):
                # default behavior
                if resp.is_redirect():
                    return resp.headers_()['location']
                # edge case - check to see if 'location' is in headers anyways
                location = resp.headers_().get('location')
                if location and (location != resp.url_()):
                    return location
                return None

        session = CustomRedirectSession()
        r = session.get(urls_test[0])
        assert len(r.history_()) == 2
        assert r.status_code_() == 200
        assert r.history_()[0].status_code_() == 302
        assert r.history_()[0].is_redirect()
        assert r.history_()[1].status_code_() == 200
        assert not r.history_()[1].is_redirect()
        assert r.url_() == urls_test[2]


class TestCaseInsensitiveDict:

    @pytest.mark.parametrize(
        'cid', (
            CaseInsensitiveDict({'Foo': 'foo', 'BAr': 'bar'}),
            CaseInsensitiveDict([('Foo', 'foo'), ('BAr', 'bar')]),
            CaseInsensitiveDict(FOO='foo', BAr='bar'),
        ))
    def test_init(self, cid):
        assert len(cid) == 2
        assert 'foo' in cid
        assert 'bar' in cid

    def test_docstring_example(self):
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        assert cid['aCCEPT'] == 'application/json'
        assert list(cid) == ['Accept']

    def test_len(self):
        cid = CaseInsensitiveDict({'a': 'a', 'b': 'b'})
        cid['A'] = 'a'
        assert len(cid) == 2

    def test_getitem(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        assert cid['spam'] == 'blueval'
        assert cid['SPAM'] == 'blueval'

    def test_fixes_649(self):
        """__setitem__ should behave case-insensitively."""
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['Spam'] = 'twoval'
        cid['sPAM'] = 'redval'
        cid['SPAM'] = 'blueval'
        assert cid['spam'] == 'blueval'
        assert cid['SPAM'] == 'blueval'
        assert list(cid.keys()) == ['SPAM']

    def test_delitem(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        del cid['sPam']
        assert 'spam' not in cid
        assert len(cid) == 0

    def test_contains(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        assert 'Spam' in cid
        assert 'spam' in cid
        assert 'SPAM' in cid
        assert 'sPam' in cid
        assert 'notspam' not in cid

    def test_get(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['SPAM'] = 'blueval'
        assert cid.get('spam') == 'blueval'
        assert cid.get('SPAM') == 'blueval'
        assert cid.get('sPam') == 'blueval'
        assert cid.get('notspam', 'default') == 'default'

    def test_update(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'blueval'
        cid.update({'sPam': 'notblueval'})
        assert cid['spam'] == 'notblueval'
        cid = CaseInsensitiveDict({'Foo': 'foo', 'BAr': 'bar'})
        cid.update({'fOO': 'anotherfoo', 'bAR': 'anotherbar'})
        assert len(cid) == 2
        assert cid['foo'] == 'anotherfoo'
        assert cid['bar'] == 'anotherbar'

    def test_update_retains_unchanged(self):
        cid = CaseInsensitiveDict({'foo': 'foo', 'bar': 'bar'})
        cid.update({'foo': 'newfoo'})
        assert cid['bar'] == 'bar'

    def test_iter(self):
        cid = CaseInsensitiveDict({'Spam': 'spam', 'Eggs': 'eggs'})
        keys = frozenset(['Spam', 'Eggs'])
        assert frozenset(iter(cid)) == keys

    def test_equality(self):
        cid = CaseInsensitiveDict({'SPAM': 'blueval', 'Eggs': 'redval'})
        othercid = CaseInsensitiveDict({'spam': 'blueval', 'eggs': 'redval'})
        assert cid == othercid
        del othercid['spam']
        assert cid != othercid
        assert cid == {'spam': 'blueval', 'eggs': 'redval'}
        assert cid != object()

    def test_setdefault(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        assert cid.setdefault('spam', 'notblueval') == 'blueval'
        assert cid.setdefault('notspam', 'notblueval') == 'notblueval'

    def test_lower_items(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        keyset = frozenset(lowerkey for lowerkey, v in cid.lower_items())
        lowerkeyset = frozenset(['accept', 'user-agent'])
        assert keyset == lowerkeyset

    def test_preserve_key_case(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        keyset = frozenset(['Accept', 'user-Agent'])
        assert frozenset(i[0] for i in cid.items()) == keyset
        assert frozenset(cid.keys()) == keyset
        assert frozenset(cid) == keyset

    def test_preserve_last_key_case(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        cid.update({'ACCEPT': 'application/json'})
        cid['USER-AGENT'] = 'requests'
        keyset = frozenset(['ACCEPT', 'USER-AGENT'])
        assert frozenset(i[0] for i in cid.items()) == keyset
        assert frozenset(cid.keys()) == keyset
        assert frozenset(cid) == keyset

    def test_copy(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        cid_copy = cid.copy()
        assert cid == cid_copy
        cid['changed'] = True
        assert cid != cid_copy


class TestMorselToCookieExpires:
    """Tests for morsel_to_cookie when morsel contains expires."""

    def test_expires_valid_str(self):
        """Test case where we convert expires from string time."""

        morsel = XMorsel()
        morsel['expires'] = 'Thu, 01-Jan-1970 00:00:01 GMT'
        cookie = CookieUtils().morsel_to_cookie(morsel)
        assert cookie.expires == 1

    @pytest.mark.parametrize(
        'value, exception', (
            (100, TypeError),
            ('woops', ValueError),
        ))
    def test_expires_invalid_int(self, value, exception):
        """Test case where an invalid type is passed for expires."""
        morsel = XMorsel()
        morsel['expires'] = value
        with pytest.raises(exception):
            CookieUtils().morsel_to_cookie(morsel)

    def test_expires_none(self):
        """Test case where expires is None."""

        morsel = XMorsel()
        morsel['expires'] = None
        cookie = CookieUtils().morsel_to_cookie(morsel)
        assert cookie.expires is None


class TestMorselToCookieMaxAge:

    """Tests for morsel_to_cookie when morsel contains max-age."""

    def test_max_age_valid_int(self):
        """Test case where a valid max age in seconds is passed."""

        morsel = XMorsel()
        morsel['max-age'] = 60
        cookie = CookieUtils().morsel_to_cookie(morsel)
        assert isinstance(cookie.expires, int)

    def test_max_age_invalid_str(self):
        """Test case where a invalid max age is passed."""

        morsel = XMorsel()
        morsel['max-age'] = 'woops'
        with pytest.raises(TypeError):
            CookieUtils().morsel_to_cookie(morsel)


class TestTimeout:

    def test_stream_timeout(self, httpbin):
        try:
            Requests().get(httpbin('delay/10'), timeout=2.0)
        except exceptions.Timeout as e:
            assert 'Read timed out' in e.args[0].args[0]

    @pytest.mark.parametrize(
        'timeout, error_text', (
            ((3, 4, 5), '(connect, read)'),
            ('foo', 'must be an int, float or None'),
        ))
    def test_invalid_timeout(self, httpbin, timeout, error_text):
        with pytest.raises(ValueError) as e:
            Requests().get(httpbin('get'), timeout=timeout)
        assert error_text in XCompat().str(e)

    @pytest.mark.parametrize(
        'timeout', (
            None,
            Urllib3Timeout(connect=None, read=None)
        ))
    def test_none_timeout(self, httpbin, timeout):
        """Check that you can set None as a valid timeout value.

        To actually test this behavior, we'd want to check that setting the
        timeout to None actually lets the request block past the system default
        timeout. However, this would make the test suite unbearably slow.
        Instead we verify that setting the timeout to None does not prevent the
        request from succeeding.
        """
        r = Requests().get(httpbin('get'), timeout=timeout)
        assert r.status_code_() == 200

    @pytest.mark.parametrize(
        'timeout', (
            (None, 0.1),
            Urllib3Timeout(connect=None, read=0.1)
        ))
    def test_read_timeout(self, httpbin, timeout):
        try:
            Requests().get(httpbin('delay/10'), timeout=timeout)
            pytest.fail('The recv() request should time out.')
        except exceptions.ReadTimeout:
            pass

    @pytest.mark.parametrize(
        'timeout', (
            (0.1, None),
            Urllib3Timeout(connect=0.1, read=None)
        ))
    def test_connect_timeout(self, timeout):
        try:
            Requests().get(TARPIT, timeout=timeout)
            pytest.fail('The connect() request should time out.')
        except exceptions.ConnectTimeout as e:
            assert isinstance(e, exceptions.ConnectionError)
            assert isinstance(e, exceptions.Timeout)

    @pytest.mark.parametrize(
        'timeout', (
            (0.1, 0.1),
            Urllib3Timeout(connect=0.1, read=0.1)
        ))
    def test_total_timeout_connect(self, timeout):
        try:
            Requests().get(TARPIT, timeout=timeout)
            pytest.fail('The connect() request should time out.')
        except exceptions.ConnectTimeout:
            pass

    def test_encoded_methods(self, httpbin):
        """See: https://github.com/psf/requests/issues/2316"""
        r = Requests().request(b'GET', httpbin('get'))
        assert r.ok()


SendCall = collections.namedtuple('SendCall', ('args', 'kwargs'))


class RedirectSession(SessionRedirectMixin):
    def __init__(self, order_of_redirects):
        self.redirects = order_of_redirects
        self.calls = []
        self.max_redirects = 30
        self.cookies_({})
        self.trust_env = False

    def send(self, *args, **kwargs):
        self.calls.append(SendCall(args, kwargs))
        return self.build_response()

    def build_response(self):
        request = self.calls[-1].args[0]
        r = Response()

        try:
            r.status_code_(int(self.redirects.pop(0)))
        except IndexError:
            r.status_code_(200)

        r.headers_(CaseInsensitiveDict({'Location': '/'}))
        r.raw_(self._build_raw())
        r.request_(request)
        return r

    def _build_raw(self):
        string = CompatStringIO.StringIO('')
        setattr(string, 'release_conn', lambda *args: args)
        return string


def test_json_encodes_as_bytes():
    # urllib3 expects bodies as bytes-like objects
    body = {"key": "value"}
    p = PreparedRequest()
    p.prepare(
        method='GET',
        url='https://www.example.com/',
        json=body
    )
    assert isinstance(p.body_(), bytes)


def test_requests_are_updated_each_time(httpbin):
    session = RedirectSession([303, 307])
    prep = Request().method_('POST').url_(httpbin('post')).prepare()
    r0 = session.send(prep)
    assert r0.request_().method_() == 'POST'
    assert session.calls[-1] == SendCall((r0.request_(),), {})
    redirect_generator = session.resolve_redirects(r0, prep)
    default_keyword_args = {
        'stream': False,
        'verify': True,
        'cert': None,
        'timeout': None,
        'allow_redirects': False,
        'proxies': {},
    }
    for response in redirect_generator:
        assert response.request_().method_() == 'GET'
        send_call = SendCall((response.request_(),), default_keyword_args)
        assert session.calls[-1] == send_call


@pytest.mark.parametrize("var,url,proxy", [
    ('http_proxy', 'http://example.com', 'socks5://proxy.com:9876'),
    ('https_proxy', 'https://example.com', 'socks5://proxy.com:9876'),
    ('all_proxy', 'http://example.com', 'socks5://proxy.com:9876'),
    ('all_proxy', 'https://example.com', 'socks5://proxy.com:9876'),
])
def test_proxy_env_vars_override_default(var, url, proxy):
    session = Session()
    prep = PreparedRequest()
    prep.prepare(method='GET', url=url)

    kwargs = {
        var: proxy
    }
    scheme = XCompat().urlparse(url).scheme
    with override_environ(**kwargs):
        proxies = session.rebuild_proxies(prep, {})
        assert scheme in proxies
        assert proxies[scheme] == proxy


@pytest.mark.parametrize(
    'data', (
        (('a', 'b'), ('c', 'd')),
        (('c', 'd'), ('a', 'b')),
        (('a', 'b'), ('c', 'd'), ('e', 'f')),
    ))
def test_data_argument_accepts_tuples(data):
    """Ensure that the data argument will accept tuples of strings
    and properly encode them.
    """
    p = PreparedRequest()
    p.prepare(
        method='GET',
        url='http://www.example.com',
        data=data,
        hooks=Hooks().default_hooks()
    )
    assert p.body_() == XCompat().urlencode(data)


@pytest.mark.parametrize(
    'kwargs', (
        None,
        {
            'method': 'GET',
            'url': 'http://www.example.com',
            'data': 'foo=bar',
            'hooks': Hooks().default_hooks()
        },
        {
            'method': 'GET',
            'url': 'http://www.example.com',
            'data': 'foo=bar',
            'hooks': Hooks().default_hooks(),
            'cookies': {'foo': 'bar'}
        },
        {
            'method': 'GET',
            'url': u('http://www.example.com/üniçø∂é')
        },
    ))
def test_prepared_copy(kwargs):
    p = PreparedRequest()
    if kwargs:
        p.prepare(**kwargs)
    copy = p.copy()
    for attr in ('method', 'url', 'headers', '_cookies', 'body', 'hooks'):
        assert getattr(p, attr) == getattr(copy, attr)


def test_urllib3_retries(httpbin):
    from urllib3.util import Retry
    s = Session()
    s.mount('http://', HTTPAdapter(max_retries=Retry(
        total=2, status_forcelist=[500]
    )))

    with pytest.raises(exceptions.RetryError):
        s.get(httpbin('status/500'))


def test_urllib3_pool_connection_closed(httpbin):
    s = Session()
    s.mount('http://', HTTPAdapter(xpool_connections=0, pool_maxsize=0))

    try:
        s.get(httpbin('status/200'))
    except exceptions.ConnectionError as e:
        assert u"Pool is closed." in XCompat().str(e)


class TestPreparingURLs(object):
    @pytest.mark.parametrize(
        'url,expected',
        (
            ('http://google.com', 'http://google.com/'),
            (u'http://ジェーピーニック.jp', u'http://xn--hckqz9bzb1cyrb.jp/'),
            (u'http://xn--n3h.net/', u'http://xn--n3h.net/'),
            (
                u'http://ジェーピーニック.jp'.encode('utf-8'),
                u'http://xn--hckqz9bzb1cyrb.jp/'
            ),
            (
                u'http://straße.de/straße',
                u'http://xn--strae-oqa.de/stra%C3%9Fe'
            ),
            (
                u'http://straße.de/straße'.encode('utf-8'),
                u'http://xn--strae-oqa.de/stra%C3%9Fe'
            ),
            (
                u'http://Königsgäßchen.de/straße',
                u'http://xn--knigsgchen-b4a3dun.de/stra%C3%9Fe'
            ),
            (
                u'http://Königsgäßchen.de/straße'.encode('utf-8'),
                u'http://xn--knigsgchen-b4a3dun.de/stra%C3%9Fe'
            ),
            (
                b'http://xn--n3h.net/',
                u'http://xn--n3h.net/'
            ),
            (
                b'http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/',
                u'http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/'
            ),
            (
                u'http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/',
                u'http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/'
            )
        )
    )
    def test_preparing_url(self, url, expected):

        def normalize_percent_encode(x):
            # Helper function that normalizes equivalent 
            # percent-encoded bytes before comparisons
            for c in re.findall(r'%[a-fA-F0-9]{2}', x):
                x = x.replace(c, c.upper())
            return x
        
        r = Request().method_('GET').url_(url)
        p = r.prepare()
        assert normalize_percent_encode(p.url_()) == expected

    @pytest.mark.parametrize(
        'url',
        (
            b"http://*.google.com",
            b"http://*",
            u"http://*.google.com",
            u"http://*",
            u"http://☃.net/"
        )
    )
    def test_preparing_bad_url(self, url):
        r = Request().method_('GET').url_(url)
        with pytest.raises(exceptions.InvalidURL):
            r.prepare()

    @pytest.mark.parametrize(
        'url, exception',
        (
            ('http://localhost:-1', exceptions.InvalidURL),
        )
    )
    def test_redirecting_to_bad_url(self, httpbin, url, exception):
        with pytest.raises(exception):
            r = Requests().get(httpbin('redirect-to'), params={'url': url})

    @pytest.mark.parametrize(
        'input, expected',
        (
            (
                b"http+unix://%2Fvar%2Frun%2Fsocket/path%7E",
                u"http+unix://%2Fvar%2Frun%2Fsocket/path~",
            ),
            (
                u"http+unix://%2Fvar%2Frun%2Fsocket/path%7E",
                u"http+unix://%2Fvar%2Frun%2Fsocket/path~",
            ),
            (
                b"mailto:user@example.org",
                u"mailto:user@example.org",
            ),
            (
                u"mailto:user@example.org",
                u"mailto:user@example.org",
            ),
            (
                b"data:SSDimaUgUHl0aG9uIQ==",
                u"data:SSDimaUgUHl0aG9uIQ==",
            )
        )
    )
    def test_url_mutation(self, input, expected):
        """
        This test validates that we correctly exclude some URLs from
        preparation, and that we handle others. Specifically, it tests that
        any URL whose scheme doesn't begin with "http" is left alone, and
        those whose scheme *does* begin with "http" are mutated.
        """
        r = Request().method_('GET').url_(input)
        p = r.prepare()
        assert p.url_() == expected

    @pytest.mark.parametrize(
        'input, params, expected',
        (
            (
                b"http+unix://%2Fvar%2Frun%2Fsocket/path",
                {"key": "value"},
                u"http+unix://%2Fvar%2Frun%2Fsocket/path?key=value",
            ),
            (
                u"http+unix://%2Fvar%2Frun%2Fsocket/path",
                {"key": "value"},
                u"http+unix://%2Fvar%2Frun%2Fsocket/path?key=value",
            ),
            (
                b"mailto:user@example.org",
                {"key": "value"},
                u"mailto:user@example.org",
            ),
            (
                u"mailto:user@example.org",
                {"key": "value"},
                u"mailto:user@example.org",
            ),
        )
    )
    def test_parameters_for_nonstandard_schemes(self, input, params, expected):
        """
        Setting parameters for nonstandard schemes is allowed if those schemes
        begin with "http", and is forbidden otherwise.
        """
        r = Request().method_('GET').url_(input).params_(params)
        p = r.prepare()
        assert p.url_() == expected

    def test_post_json_nan(self, httpbin):
        data = {"foo": float("nan")}
        with pytest.raises(exceptions.InvalidJSONError):
          r = Requests().post(httpbin('post'), json=data)

    def test_json_decode_compatibility(self, httpbin):
        r = Requests().get(httpbin('bytes/20'))
        with pytest.raises(exceptions.JSONDecodeError):
            r.json()
