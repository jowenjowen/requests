# -*- coding: utf-8 -*-

# domain.py contains the code related to the domain
# (use an ide showing class structures for navigation)

from requests.x import XPlatform, XJson, XUrllib3, XSys, XCharSetNormalizer, XCharDet, \
    XOpenSSL, XIdna, XCryptography, XSsl, XPyOpenSsl, XMutableMapping, XOrderedDict, XMapping

# classes needed for Auth section
from requests.x import basestring, XBaseString, XWarnings, XBase64, XHashLib, XTime, XOs, XRe
from .compat import str

# classes needed for InternalUtilitites
from requests.x import XCompat, XThreading # is_py2, builtin_str, str

# imports needed for Utils
from .compat import parse_http_list as _parse_list_header

# imports needed for Exceptions
from urllib3.exceptions import HTTPError as BaseHTTPError
from .compat import JSONDecodeError as CompatJSONDecodeError

# imports needed for Certs
from certifi import where as certifi_where

# imports needed for Cookies2
from .x import XCopy, XCalendar
from .x import XMorsel

from . import __version__ as requests_version

#         Help
#             class Help
#         Api
#             class Api
#         Structures
#             class Structures


# *************************** classes in InternalUtilities section *****************
class _Internal_utils:  # ./InternalUtils/internal_utils.py
    """
    requests._internal_utils
    ~~~~~~~~~~~~~~

    Provides utility functions that are consumed internally by Requests
    which depend on extremely few external helpers (such as compat)
    """

    def to_native_string(self, string, encoding='ascii'):
        """Given a string object, regardless of type, returns a representation of
        that string in the native string type, encoding and decoding where
        necessary. This assumes ASCII unless told otherwise.
        """
        if XCompat().is_builtin_str_instance(string):
            out = string
        else:
            if XCompat().is_py2():
                out = string.encode(encoding)
            else:
                out = string.decode(encoding)

        return out

    def unicode_is_ascii(self, u_string):
        """Determine if unicode string only contains ASCII characters.

        :param str u_string: unicode string to check. Must be unicode
            and not Python 2 `str`.
        :rtype: bool
        """
        assert isinstance(u_string, str)
        try:
            u_string.encode('ascii')
            return True
        except UnicodeEncodeError:
            return False


# *************************** classes in Auth section *****************
class Auth:  # ./Auth/auth.py

    CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
    CONTENT_TYPE_MULTI_PART = 'multipart/form-data'

    def basic_auth_str(self, username, password):
        """Returns a Basic Auth string."""

        # "I want us to put a big-ol' comment on top of it that
        # says that this behaviour is dumb but we need to preserve
        # it because people are relying on it."
        #    - Lukasa
        #
        # These are here solely to maintain backwards compatibility
        # for things like ints. This will be removed in 3.0.0.
        if not isinstance(username, basestring):
            XWarnings().warn((
                "Non-string usernames will no longer be supported in Requests "
                "3.0.0. Please convert the object you've passed in ({!r}) to "
                "a string or bytes object in the near future to avoid "
                "problems.".format(username)),
                category=DeprecationWarning,
            )
            username = str(username)

        if not isinstance(password, basestring):
            XWarnings().warn((
                "Non-string passwords will no longer be supported in Requests "
                "3.0.0. Please convert the object you've passed in ({!r}) to "
                "a string or bytes object in the near future to avoid "
                "problems.".format(type(password))),
                category=DeprecationWarning,
            )
            password = str(password)
        # -- End Removal --

        if isinstance(username, str):
            username = username.encode('latin1')

        if isinstance(password, str):
            password = password.encode('latin1')

        authstr = 'Basic ' + _Internal_utils().to_native_string(
            XBase64().b64encode(b':'.join((username, password))).strip()
        )

        return authstr

class AuthBase(object):
    """Base class that all auth implementations derive from"""

    def __call__(self, r):
        raise NotImplementedError('Auth hooks must be callable.')

class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __eq__(self, other):
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = Auth().basic_auth_str(self.username, self.password)
        return r

class HTTPProxyAuth(HTTPBasicAuth):
    """Attaches HTTP Proxy Authentication to a given Request object."""

    def __call__(self, r):
        r.headers['Proxy-Authorization'] = Auth().basic_auth_str(self.username, self.password)
        return r

class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = username
        self.password = password
        # Keep state in per-thread local storage
        self._thread_local = XThreading().local()

    def init_per_thread_state(self):
        # Ensure state is initialized just once per-thread
        if not hasattr(self._thread_local, 'init'):
            self._thread_local.init = True
            self._thread_local.last_nonce = ''
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    def build_digest_header(self, method, url):
        """
        :rtype: str
        """

        realm = self._thread_local.chal['realm']
        nonce = self._thread_local.chal['nonce']
        qop = self._thread_local.chal.get('qop')
        algorithm = self._thread_local.chal.get('algorithm')
        opaque = self._thread_local.chal.get('opaque')
        hash_utf8 = None

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return XHashLib().md5(x).hexdigest()

            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return XHashLib().sha1(x).hexdigest()

            hash_utf8 = sha_utf8
        elif _algorithm == 'SHA-256':
            def sha256_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return XHashLib().sha256(x).hexdigest()

            hash_utf8 = sha256_utf8
        elif _algorithm == 'SHA-512':
            def sha512_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return XHashLib().sha512(x).hexdigest()

            hash_utf8 = sha512_utf8

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = XCompat().urlparse(url)
        #: path is request-uri defined in RFC 2616 which should not be empty
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += '?' + p_parsed.query

        A1 = '%s:%s:%s' % (self.username, realm, self.password)
        A2 = '%s:%s' % (method, path)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = '%08x' % self._thread_local.nonce_count
        s = str(self._thread_local.nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += XTime().ctime().encode('utf-8')
        s += XOs().urandom(8)

        cnonce = (XHashLib().sha1(s).hexdigest()[:16])
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s' % (HA1, nonce, cnonce))

        if not qop:
            respdig = KD(HA1, "%s:%s" % (nonce, HA2))
        elif qop == 'auth' or 'auth' in qop.split(','):
            noncebit = "%s:%s:%s:%s:%s" % (
                nonce, ncvalue, cnonce, 'auth', HA2
            )
            respdig = KD(HA1, noncebit)
        else:
            # XXX handle auth-int.
            return None

        self._thread_local.last_nonce = nonce

        # XXX should the partial digests be encoded too?
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (self.username, realm, nonce, path, respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if entdig:
            base += ', digest="%s"' % entdig
        if qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)

    def handle_redirect(self, r, **kwargs):
        """Reset num_401_calls counter on redirects."""
        if r.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, r, **kwargs):
        """
        Takes the given response and tries digest-auth, if needed.

        :rtype: requests.Response
        """

        # If response is not 4xx, do not auth
        # See https://github.com/psf/requests/issues/3772
        if not 400 <= r.status_code < 500:
            self._thread_local.num_401_calls = 1
            return r

        if self._thread_local.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request.body.seek(self._thread_local.pos)
        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = XRe().compile(r'digest ', flags=XRe().IGNORECASE())
            self._thread_local.chal = Utils().parse_dict_header(pat.sub('', s_auth, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.close()
            prep = r.request.copy()
            Cookies().extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Authorization'] = self.build_digest_header(
                prep.method, prep.url)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):
        # Initialize per-thread state, if needed
        self.init_per_thread_state()
        # If we have a saved nonce, skip the 401
        if self._thread_local.last_nonce:
            r.headers['Authorization'] = self.build_digest_header(r.method, r.url)
        try:
            self._thread_local.pos = r.body.tell()
        except AttributeError:
            # In the case of HTTPDigestAuth being reused and the body of
            # the previous request was a file-like object, pos has the
            # file position of the previous body. Ensure it's set to
            # None.
            self._thread_local.pos = None
        r.register_hook('response', self.handle_401)
        r.register_hook('response', self.handle_redirect)
        self._thread_local.num_401_calls = 1

        return r

    def __eq__(self, other):
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other


# *************************** classes in Certs section *****************

class Certs:  # ./Certs/Certs.py
    """
    requests.certs
    ~~~~~~~~~~~~~~

    This module returns the preferred default CA certificate bundle. There is
    only one — the one from the certifi package.

    If you are packaging Requests, e.g., for a Linux distribution or a managed
    environment, you can change the definition of where() to return a separately
    packaged CA bundle.
    """

    def where(self):
        return certifi_where()


# *************************** classes in Cookies section *****************

class MockRequest(object):
    """Wraps a `requests.Request` to mimic a `urllib2.Request`.

    The code in `cookielib.CookieJar` expects this interface in order to correctly
    manage cookie policies, i.e., determine whether a cookie can be set, given the
    domains of the request and the cookie.

    The original request object is read-only. The client is responsible for collecting
    the new headers via `get_new_headers()` and interpreting them appropriately. You
    probably want `get_cookie_header`, defined below.
    """

    def __init__(self, request):
        self._r = request
        self._new_headers = {}
        self.type = XCompat().urlparse(self._r.url).scheme

    def get_type(self):
        return self.type

    def get_host(self):
        return XCompat().urlparse(self._r.url).netloc

    def get_origin_req_host(self):
        return self.get_host()

    def get_full_url(self):
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self._r.headers.get('Host'):
            return self._r.url
        # If they did set it, retrieve it and reconstruct the expected domain
        host = _Internal_utils().to_native_string(self._r.headers['Host'], encoding='utf-8')
        parsed = XCompat().urlparse(self._r.url)
        # Reconstruct the URL as we expect it
        return XCompat().urlunparse([
            parsed.scheme, host, parsed.path, parsed.params, parsed.query,
            parsed.fragment
        ])

    def is_unverifiable(self):
        return True

    def has_header(self, name):
        return name in self._r.headers or name in self._new_headers

    def get_header(self, name, default=None):
        return self._r.headers.get(name, self._new_headers.get(name, default))

    def add_header(self, key, val):
        """cookielib has no legitimate use for this method; add it back if you find one."""
        raise NotImplementedError("Cookie headers should be added with add_unredirected_header()")

    def add_unredirected_header(self, name, value):
        self._new_headers[name] = value

    def get_new_headers(self):
        return self._new_headers

    @property
    def unverifiable(self):
        return self.is_unverifiable()

    @property
    def origin_req_host(self):
        return self.get_origin_req_host()

    @property
    def host(self):
        return self.get_host()


class MockResponse(object):
    """Wraps a `httplib.HTTPMessage` to mimic a `urllib.addinfourl`.

    ...what? Basically, expose the parsed HTTP headers from the server response
    the way `cookielib` expects to see them.
    """

    def __init__(self, headers):
        """Make a MockResponse for `cookielib` to read.

        :param headers: a httplib.HTTPMessage or analogous carrying the headers
        """
        self._headers = headers

    def info(self):
        return self._headers

    def getheaders(self, name):
        self._headers.getheaders(name)


class Cookies:  # ./Cookies/Cookies.py
    def extract_cookies_to_jar(self, jar, request, response):
        """Extract the cookies from the response into a CookieJar.

        :param jar: cookielib.CookieJar (not necessarily a RequestsCookieJar)
        :param request: our own requests.Request object
        :param response: urllib3.HTTPResponse object
        """
        if not (hasattr(response, '_original_response') and
                response._original_response):
            return
        # the _original_response field is the wrapped httplib.HTTPResponse object,
        req = MockRequest(request)
        # pull out the HTTPMessage with the headers and put it in the mock:
        res = MockResponse(response._original_response.msg)
        jar.extract_cookies(res, req)

    def get_cookie_header(self, jar, request):
        """
        Produce an appropriate Cookie header string to be sent with `request`, or None.

        :rtype: str
        """
        r = MockRequest(request)
        jar.add_cookie_header(r)
        return r.get_new_headers().get('Cookie')

    def remove_cookie_by_name(self, cookiejar, name, domain=None, path=None):
        """Unsets a cookie by name, by default over all domains and paths.

        Wraps CookieJar.clear(), is O(n).
        """
        clearables = []
        for cookie in cookiejar:
            if cookie.name != name:
                continue
            if domain is not None and domain != cookie.domain:
                continue
            if path is not None and path != cookie.path:
                continue
            clearables.append((cookie.domain, cookie.path, cookie.name))

        for domain, path, name in clearables:
            cookiejar.clear(domain, path, name)


class CookieConflictError(RuntimeError):
    """There are two cookies that meet the criteria specified in the cookie jar.
    Use .get and .set and include domain and path args in order to be more specific.
    """


class RequestsCookieJar(XCompat().cookielib().CookieJar, XMutableMapping):
    """Compatibility class; is a cookielib.CookieJar, but exposes a dict
    interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Requests does not use the dict interface internally; it's just for
    compatibility with external client code. All requests code should work
    out of the box with externally provided instances of ``CookieJar``, e.g.
    ``LWPCookieJar`` and ``FileCookieJar``.

    Unlike a regular CookieJar, this class is pickleable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
    """

    def get(self, name, default=None, domain=None, path=None):
        """Dict-like get() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.

        .. warning:: operation is O(n), not O(1).
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        """Dict-like set() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.
        """
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            Cookies().remove_cookie_by_name(self, name, domain=kwargs.get('domain'), path=kwargs.get('path'))
            return

        if isinstance(value, XMorsel):
            c = self.morsel_to_cookie(value)
        else:
            c = Cookies2().create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self):
        """Dict-like iterkeys() that returns an iterator of names of cookies
        from the jar.

        .. seealso:: itervalues() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self):
        """Dict-like keys() that returns a list of names of cookies from the
        jar.

        .. seealso:: values() and items().
        """
        return list(self.iterkeys())

    def itervalues(self):
        """Dict-like itervalues() that returns an iterator of values of cookies
        from the jar.

        .. seealso:: iterkeys() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self):
        """Dict-like values() that returns a list of values of cookies from the
        jar.

        .. seealso:: keys() and items().
        """
        return list(self.itervalues())

    def iteritems(self):
        """Dict-like iteritems() that returns an iterator of name-value tuples
        from the jar.

        .. seealso:: iterkeys() and itervalues().
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self):
        """Dict-like items() that returns a list of name-value tuples from the
        jar. Allows client-code to call ``dict(RequestsCookieJar)`` and get a
        vanilla python dict of key value pairs.

        .. seealso:: keys() and values().
        """
        return list(self.iteritems())

    def list_domains(self):
        """Utility method to list all the domains in the jar."""
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self):
        """Utility method to list all the paths in the jar."""
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self):
        """Returns True if there are multiple domains in the jar.
        Returns False otherwise.

        :rtype: bool
        """
        domains = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(self, domain=None, path=None):
        """Takes as an argument an optional domain and path and returns a plain
        old Python dict of name-value pairs of cookies that meet the
        requirements.

        :rtype: dict
        """
        dictionary = {}
        for cookie in iter(self):
            if (
                (domain is None or cookie.domain == domain) and
                (path is None or cookie.path == path)
            ):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __contains__(self, name):
        try:
            return super(RequestsCookieJar, self).__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name):
        """Dict-like __getitem__() for compatibility with client code. Throws
        exception if there are more than one cookie with name. In that case,
        use the more explicit get() method instead.

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name, value):
        """Dict-like __setitem__ for compatibility with client code. Throws
        exception if there is already a cookie of that name in the jar. In that
        case, use the more explicit set() method instead.
        """
        self.set(name, value)

    def __delitem__(self, name):
        """Deletes a cookie given a name. Wraps ``cookielib.CookieJar``'s
        ``remove_cookie_by_name()``.
        """
        Cookies().remove_cookie_by_name(self, name)

    def set_cookie(self, cookie, *args, **kwargs):
        if hasattr(cookie.value, 'startswith') and cookie.value.startswith('"') and cookie.value.endswith('"'):
            cookie.value = cookie.value.replace('\\"', '')
        return super(RequestsCookieJar, self).set_cookie(cookie, *args, **kwargs)

    def update(self, other):
        """Updates this jar with cookies from another CookieJar or dict-like"""
        if isinstance(other, XCompat().cookielib().CookieJar):
            for cookie in other:
                self.set_cookie(XCopy().copy(cookie))
        else:
            super(RequestsCookieJar, self).update(other)

    def _find(self, name, domain=None, path=None):
        """Requests uses this method internally to get cookie values.

        If there are conflicting cookies, _find arbitrarily chooses one.
        See _find_no_duplicates if you want an exception thrown if there are
        conflicting cookies.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :return: cookie.value
        """
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

    def _find_no_duplicates(self, name, domain=None, path=None):
        """Both ``__get_item__`` and ``get`` call this function: it's never
        used elsewhere in Requests.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :raises KeyError: if cookie is not found
        :raises CookieConflictError: if there are multiple cookies
            that match name and optionally domain and path
        :return: cookie.value
        """
        toReturn = None
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if toReturn is not None:  # if there are multiple cookies that meet passed in criteria
                            raise CookieConflictError('There are multiple cookies with name, %r' % (name))
                        toReturn = cookie.value  # we will eventually return this as long as no cookie conflict

        if toReturn:
            return toReturn
        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

    def __getstate__(self):
        """Unlike a normal CookieJar, this class is pickleable."""
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop('_cookies_lock')
        return state

    def __setstate__(self, state):
        """Unlike a normal CookieJar, this class is pickleable."""
        self.__dict__.update(state)
        if '_cookies_lock' not in self.__dict__:
            self._cookies_lock = XThreading().RLock()

    def copy(self):
        """Return a copy of this RequestsCookieJar."""
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self):
        """Return the CookiePolicy instance used."""
        return self._policy


class Cookies2:  # ./Cookies/Cookies2.py
    def _copy_cookie_jar(self, jar):
        if jar is None:
            return None

        if hasattr(jar, 'copy'):
            # We're dealing with an instance of RequestsCookieJar
            return jar.copy()
        # We're dealing with a generic CookieJar instance
        new_jar = XCopy().copy(jar)
        new_jar.clear()
        for cookie in jar:
            new_jar.set_cookie(XCopy().copy(cookie))
        return new_jar

    def create_cookie(self, name, value, **kwargs):
        """Make a cookie from underspecified parameters.

        By default, the pair of `name` and `value` will be set for the domain ''
        and sent on every request (this is sometimes called a "supercookie").
        """
        result = {
            'version': 0,
            'name': name,
            'value': value,
            'port': None,
            'domain': '',
            'path': '/',
            'secure': False,
            'expires': None,
            'discard': True,
            'comment': None,
            'comment_url': None,
            'rest': {'HttpOnly': None},
            'rfc2109': False,
        }

        badargs = set(kwargs) - set(result)
        if badargs:
            err = 'create_cookie() got unexpected keyword arguments: %s'
            raise TypeError(err % list(badargs))

        result.update(kwargs)
        result['port_specified'] = bool(result['port'])
        result['domain_specified'] = bool(result['domain'])
        result['domain_initial_dot'] = result['domain'].startswith('.')
        result['path_specified'] = bool(result['path'])

        return XCompat().cookielib().Cookie(**result)

    def morsel_to_cookie(self, morsel):
        """Convert a Morsel object into a Cookie containing the one k/v pair."""

        expires = None
        if morsel['max-age']:
            try:
                expires = int(XTime().time() + int(morsel['max-age']))
            except ValueError:
                raise TypeError('max-age: %s must be integer' % morsel['max-age'])
        elif morsel['expires']:
            time_template = '%a, %d-%b-%Y %H:%M:%S GMT'
            expires = XCalendar().timegm(
                XTime().strptime(morsel['expires'], time_template)
            )
        return self.create_cookie(
            comment=morsel['comment'],
            comment_url=bool(morsel['comment']),
            discard=False,
            domain=morsel['domain'],
            expires=expires,
            name=morsel.key,
            path=morsel['path'],
            port=None,
            rest={'HttpOnly': morsel['httponly']},
            rfc2109=False,
            secure=bool(morsel['secure']),
            value=morsel.value,
            version=morsel['version'] or 0,
        )

    def cookiejar_from_dict(self, cookie_dict, cookiejar=None, overwrite=True):
        """Returns a CookieJar from a key/value dictionary.

        :param cookie_dict: Dict of key/values to insert into CookieJar.
        :param cookiejar: (optional) A cookiejar to add the cookies to.
        :param overwrite: (optional) If False, will not replace cookies
            already in the jar with new ones.
        :rtype: CookieJar
        """
        if cookiejar is None:
            cookiejar = RequestsCookieJar()

        if cookie_dict is not None:
            names_from_jar = [cookie.name for cookie in cookiejar]
            for name in cookie_dict:
                if overwrite or (name not in names_from_jar):
                    cookiejar.set_cookie(self.create_cookie(name, cookie_dict[name]))

        return cookiejar

    def merge_cookies(self, cookiejar, cookies):
        """Add cookies to cookiejar and returns a merged CookieJar.

        :param cookiejar: CookieJar object to add the cookies to.
        :param cookies: Dictionary or CookieJar object to be added.
        :rtype: CookieJar
        """
        if not isinstance(cookiejar, XCompat().cookielib().CookieJar):
            raise ValueError('You can only merge into CookieJar')

        if isinstance(cookies, dict):
            cookiejar = self.cookiejar_from_dict(
                cookies, cookiejar=cookiejar, overwrite=False)
        elif isinstance(cookies, XCompat().cookielib().CookieJar):
            try:
                cookiejar.update(cookies)
            except AttributeError:
                for cookie_in_jar in cookies:
                    cookiejar.set_cookie(cookie_in_jar)

        return cookiejar


# *************************** classes in Exceptions section *****************
"""
requests.exceptions
~~~~~~~~~~~~~~~~~~~

This section contains the set of Requests' exceptions.
"""

class RequestException(IOError):  # ./Exceptions/RequestException.py
    """There was an ambiguous exception that occurred while handling your
    request.
    """

    def __init__(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop('response', None)
        self.response = response
        self.request = kwargs.pop('request', None)
        if (response is not None and not self.request and
                hasattr(response, 'request')):
            self.request = self.response.request
        super(RequestException, self).__init__(*args, **kwargs)


class InvalidJSONError(RequestException):
    """A JSON error occurred."""


class JSONDecodeError(InvalidJSONError, CompatJSONDecodeError):
    """Couldn't decode the text into json"""


class HTTPError(RequestException):
    """An HTTP error occurred."""


class ConnectionError(RequestException):
    """A Connection error occurred."""


class ProxyError(ConnectionError):
    """A proxy error occurred."""


class SSLError(ConnectionError):
    """An SSL error occurred."""


class Timeout(RequestException):
    """The request timed out.

    Catching this error will catch both
    :exc:`~requests.exceptions.ConnectTimeout` and
    :exc:`~requests.exceptions.ReadTimeout` errors.
    """


class ConnectTimeout(ConnectionError, Timeout):
    """The request timed out while trying to connect to the remote server.

    Requests that produced this error are safe to retry.
    """


class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time."""


class URLRequired(RequestException):
    """A valid URL is required to make a request."""


class TooManyRedirects(RequestException):
    """Too many redirects."""


class MissingSchema(RequestException, ValueError):
    """The URL schema (e.g. http or https) is missing."""


class InvalidSchema(RequestException, ValueError):
    """See defaults.py for valid schemas."""


class InvalidURL(RequestException, ValueError):
    """The URL provided was somehow invalid."""


class InvalidHeader(RequestException, ValueError):
    """The header value provided was somehow invalid."""


class InvalidProxyURL(InvalidURL):
    """The proxy URL provided is invalid."""


class ChunkedEncodingError(RequestException):
    """The server declared chunked encoding but sent an invalid chunk."""


class ContentDecodingError(RequestException, BaseHTTPError):
    """Failed to decode response content."""


class StreamConsumedError(RequestException, TypeError):
    """The content for this response was already consumed."""


class RetryError(RequestException):
    """Custom retries logic failed"""


class UnrewindableBodyError(RequestException):
    """Requests encountered an error when trying to rewind a body."""

# Warnings


class RequestsWarning(Warning):
    """Base warning for Requests."""


class FileModeWarning(RequestsWarning, DeprecationWarning):
    """A file was opened in text mode, but Requests determined its binary length."""


class RequestsDependencyWarning(RequestsWarning):
    """An imported dependency doesn't match the expected version range."""

# *************************** classes in Structures section *****************

class CaseInsensitiveDict(XMutableMapping):  # ./Structures/CaseInsensitiveDict.py

    """A case-insensitive ``dict``-like object.

    Implements all methods and operations of
    ``MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.

    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::

        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.

    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.lower()``s, the
    behavior is undefined.
    """

    def __init__(self, data=None, **kwargs):
        self._store = XOrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return (
            (lowerkey, keyval[1])
            for (lowerkey, keyval)
            in self._store.items()
        )

    def __eq__(self, other):
        if isinstance(other, XMapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))

class LookupDict(dict):  # ./Structures/LookupDict.py
    """Dictionary lookup object."""

    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % (self.name)

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


# *************************** classes in Help section *****************

class Help:  # ./Help/help.py
    def __init__(self):
        pass

    def _implementation(self):
        """Return a dict with the Python implementation and version.

        Provide both the name and the version of the Python implementation
        currently running. For example, on CPython 2.7.5 it will return
        {'name': 'CPython', 'version': '2.7.5'}.

        This function works best on CPython and PyPy: in particular, it probably
        doesn't work for Jython or IronPython. Future investigation should be done
        to work out the correct shape of the code for those platforms.
        """
        implementation = XPlatform().python_implementation()

        if implementation == 'CPython':
            implementation_version = XPlatform().python_version()
        elif implementation == 'PyPy':
            implementation_version = '%s.%s.%s' % (XSys().pypy_version_info().major(),
                                                   XSys().pypy_version_info().minor(),
                                                   XSys().pypy_version_info().micro())
            if XSys().pypy_version_info().releaselevel() != 'final':
                implementation_version = ''.join([
                    implementation_version, XSys().pypy_version_info().releaselevel()
                ])
        elif implementation == 'Jython':
            implementation_version = XPlatform().python_version()  # Complete Guess
        elif implementation == 'IronPython':
            implementation_version = XPlatform().python_version()  # Complete Guess
        else:
            implementation_version = 'Unknown'

        return {'name': implementation, 'version': implementation_version}

    def info(self):
        """Generate information for a bug report."""
        try:
            platform_info = {
                'system': XPlatform().system(),
                'release': XPlatform().release(),
            }
        except IOError:
            platform_info = {
                'system': 'Unknown',
                'release': 'Unknown',
            }

        implementation_info = self._implementation()
        urllib3_info = {'version': XUrllib3().version()}
        charset_normalizer_info = {'version': None}
        chardet_info = {'version': None}
        if XCharSetNormalizer().import_works():
            charset_normalizer_info = {'version': XCharSetNormalizer().version()}
        if XCharDet().import_works():
            chardet_info = {'version': XCharDet().version()}

        pyopenssl_info = {
            'version': None,
            'openssl_version': '',
        }
        if XOpenSSL().import_works():
            pyopenssl_info = {
                'version': XOpenSSL().version(),
                'openssl_version': '%x' % XOpenSSL().openssl_version(),
            }
        cryptography_info = {
            'version':  XCryptography().version(),
        }
        idna_info = {
            'version': XIdna().version(),
        }

        system_ssl = XSsl().openssl_version()
        system_ssl_info = {
            'version': '%x' % system_ssl if system_ssl is not None else ''
        }

        return {
            'platform': platform_info,
            'implementation': implementation_info,
            'system_ssl': system_ssl_info,
            'using_pyopenssl': XPyOpenSsl().import_works(),
            'using_charset_normalizer': XCharDet().import_works(),
            'pyOpenSSL': pyopenssl_info,
            'urllib3': urllib3_info,
            'chardet': chardet_info,
            'charset_normalizer': charset_normalizer_info,
            'cryptography': cryptography_info,
            'idna': idna_info,
            'requests': {
                'version': requests_version,
            },
        }

# *************************** classes in Help section *****************

class Hooks:  # ./Hooks/hooks.py
    """
    This class provides the capabilities for the Requests hooks system.

    Available hooks:

    ``response``:
        The response generated from a Request.
    """
    def __init__(self):
        self.HOOKS = ['response']

    def default_hooks(self):
        return {event: [] for event in self.HOOKS}

    # TODO: response is the only one

    def dispatch_hook(self, key, hooks, hook_data, **kwargs):
        """Dispatches a hook dictionary on a given piece of data."""
        hooks = hooks or {}
        hooks = hooks.get(key)
        if hooks:
            if hasattr(hooks, '__call__'):
                hooks = [hooks]
            for hook in hooks:
                _hook_data = hook(hook_data, **kwargs)
                if _hook_data is not None:
                    hook_data = _hook_data
        return hook_data


# *************************** classes in StatusCodes section *****************

class StatusCodes:  # ./StatusCodes/status_codes.py
    """
    The ``codes`` object defines a mapping from common names for HTTP statuses
    to their numerical codes, accessible either as attributes or as dictionary
    items.

    Example::

        >>> import requests
        >>> requests.codes['temporary_redirect']
        307
        >>> requests.codes.teapot
        418
        >>> requests.codes['\o/']
        200

    Some codes have multiple names, and both upper- and lower-case versions of
    the names are allowed. For example, ``codes.ok``, ``codes.OK``, and
    ``codes.okay`` all correspond to the HTTP status code 200.
    """
    _codes = {

        # Informational.
        100: ('continue',),
        101: ('switching_protocols',),
        102: ('processing',),
        103: ('checkpoint',),
        122: ('uri_too_long', 'request_uri_too_long'),
        200: ('ok', 'okay', 'all_ok', 'all_okay', 'all_good', '\\o/', '✓'),
        201: ('created',),
        202: ('accepted',),
        203: ('non_authoritative_info', 'non_authoritative_information'),
        204: ('no_content',),
        205: ('reset_content', 'reset'),
        206: ('partial_content', 'partial'),
        207: ('multi_status', 'multiple_status', 'multi_stati', 'multiple_stati'),
        208: ('already_reported',),
        226: ('im_used',),

        # Redirection.
        300: ('multiple_choices',),
        301: ('moved_permanently', 'moved', '\\o-'),
        302: ('found',),
        303: ('see_other', 'other'),
        304: ('not_modified',),
        305: ('use_proxy',),
        306: ('switch_proxy',),
        307: ('temporary_redirect', 'temporary_moved', 'temporary'),
        308: ('permanent_redirect',
              'resume_incomplete', 'resume',),  # These 2 to be removed in 3.0

        # Client Error.
        400: ('bad_request', 'bad'),
        401: ('unauthorized',),
        402: ('payment_required', 'payment'),
        403: ('forbidden',),
        404: ('not_found', '-o-'),
        405: ('method_not_allowed', 'not_allowed'),
        406: ('not_acceptable',),
        407: ('proxy_authentication_required', 'proxy_auth', 'proxy_authentication'),
        408: ('request_timeout', 'timeout'),
        409: ('conflict',),
        410: ('gone',),
        411: ('length_required',),
        412: ('precondition_failed', 'precondition'),
        413: ('request_entity_too_large',),
        414: ('request_uri_too_large',),
        415: ('unsupported_media_type', 'unsupported_media', 'media_type'),
        416: ('requested_range_not_satisfiable', 'requested_range', 'range_not_satisfiable'),
        417: ('expectation_failed',),
        418: ('im_a_teapot', 'teapot', 'i_am_a_teapot'),
        421: ('misdirected_request',),
        422: ('unprocessable_entity', 'unprocessable'),
        423: ('locked',),
        424: ('failed_dependency', 'dependency'),
        425: ('unordered_collection', 'unordered'),
        426: ('upgrade_required', 'upgrade'),
        428: ('precondition_required', 'precondition'),
        429: ('too_many_requests', 'too_many'),
        431: ('header_fields_too_large', 'fields_too_large'),
        444: ('no_response', 'none'),
        449: ('retry_with', 'retry'),
        450: ('blocked_by_windows_parental_controls', 'parental_controls'),
        451: ('unavailable_for_legal_reasons', 'legal_reasons'),
        499: ('client_closed_request',),

        # Server Error.
        500: ('internal_server_error', 'server_error', '/o\\', '✗'),
        501: ('not_implemented',),
        502: ('bad_gateway',),
        503: ('service_unavailable', 'unavailable'),
        504: ('gateway_timeout',),
        505: ('http_version_not_supported', 'http_version'),
        506: ('variant_also_negotiates',),
        507: ('insufficient_storage',),
        509: ('bandwidth_limit_exceeded', 'bandwidth'),
        510: ('not_extended',),
        511: ('network_authentication_required', 'network_auth', 'network_authentication'),
    }

    _codes_dict = LookupDict(name='status_codes')

    def __init__(self):
        if self._codes_dict.__dict__.__len__() > 10:
            return
        for code, titles in self._codes.items():
            for title in titles:
                setattr(self._codes_dict, title, code)
                if not title.startswith(('\\', '/')):
                    setattr(self._codes_dict, title.upper(), code)
        pass

    def doc(self, code):
        names = ', '.join('``%s``' % n for n in _codes[code])
        return '* %d: %s' % (code, names)

    def get(self, name):
        return self._codes_dict.get(name)

# *************************** classes in Utils section *****************

class Utils:  # ./Utils/utils.py
    # From mitsuhiko/werkzeug (used with permission).
    def parse_dict_header(self, value):
        """Parse lists of key, value pairs as described by RFC 2068 Section 2 and
        convert them into a python dict:

        >>> d = parse_dict_header('foo="is a fish", bar="as well"')
        >>> type(d) is dict
        True
        >>> sorted(d.items())
        [('bar', 'as well'), ('foo', 'is a fish')]

        If there is no value for a key it will be `None`:

        >>> parse_dict_header('key_without_value')
        {'key_without_value': None}

        To create a header from the :class:`dict` again, use the
        :func:`dump_header` function.

        :param value: a string with a dict header.
        :return: :class:`dict`
        :rtype: dict
        """
        result = {}
        for item in _parse_list_header(value):
            if '=' not in item:
                result[item] = None
                continue
            name, value = item.split('=', 1)
            if value[:1] == value[-1:] == '"':
                value = self.unquote_header_value(value[1:-1])
            result[name] = value
        return result

    # From mitsuhiko/werkzeug (used with permission).
    def unquote_header_value(self, value, is_filename=False):
        r"""Unquotes a header value.  (Reversal of :func:`quote_header_value`).
        This does not use the real unquoting but what browsers are actually
        using for quoting.

        :param value: the header value to unquote.
        :rtype: str
        """
        if value and value[0] == value[-1] == '"':
            # this is not the real unquoting, but fixing this so that the
            # RFC is met will result in bugs with internet explorer and
            # probably some other browsers as well.  IE for example is
            # uploading files with "C:\foo\bar.txt" as filename
            value = value[1:-1]

            # if this is a filename and the starting characters look like
            # a UNC path, then just return the value without quotes.  Using the
            # replace sequence below on a UNC path has the effect of turning
            # the leading double slash into a single slash and then
            # _fix_ie_filename() doesn't work correctly.  See #458.
            if not is_filename or value[:2] != '\\\\':
                return value.replace('\\\\', '\\').replace('\\"', '"')
        return value



