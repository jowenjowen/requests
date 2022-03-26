#! /usr/bin/python
# -*- coding: utf-8 -*-

# domain.py contains the code related to the domain
# (use an ide showing class structures for navigation)

import sys, inspect

from requests.doop.help import Help

from .x import XPlatform, XJson, XUrllib3, XSys, XCharSetNormalizer, XCharDet, \
    XOpenSSL, XIdna, XCryptography, XSsl, XPyOpenSsl, XMutableMapping, XOrderedDict, XMapping, XUtils

from .x import XStr
from .x import XBytes
from .x import XBuiltinStr
from .x import XBaseString
from .x import XUrl

# classes needed for Auth section
from .x import XWarnings
from .x import XBase64
from .x import XHashLib
from .x import XTime
from .x import XOs
from .x import XRe

# classes needed for InternalUtilities
from .x import XCompat, XThreading

# imports needed for Utils
from requests.compat import compat_parse_http_list as _parse_list_header
from .x import XSocket, XCodecs, XIo, XTempFile, XStruct
# imports needed for Exceptions
from .x import XJSONDecodeError

# imports needed for Certs
from certifi import where as certifi_where

# imports needed for Cookies
from .x import XCopy, XCalendar
from .x import XMorsel
from .x import XCookieJar
from .x import XCookie
from .x import XCookieJarRequest
from .x import XCookieJarResponse

# imports needed for Sessions
from .x import XDateTime

#         Help
#             class Help
#         Api
#             class Api
#         Structures
#             class Structures

# imports needed for Models
from requests.compat import compat_json as complexjson

# imports needed for adapters
from .x import XZipfile
import contextlib

from requests.exceptions import FileModeWarning
from requests.exceptions import InvalidURL
from requests.exceptions import ConnectionError
from requests.exceptions import MissingSchema
from requests.exceptions import InvalidSchema
from requests.exceptions import InvalidJSONError
from requests.exceptions import HTTPError
from requests.exceptions import TooManyRedirects
from requests.exceptions import ContentDecodingError
from requests.exceptions import ChunkedEncodingError
from requests.exceptions import SSLError
from requests.exceptions import ConnectTimeout
from requests.exceptions import RetryError
from requests.exceptions import ProxyError
from requests.exceptions import UnrewindableBodyError
from requests.exceptions import ReadTimeout
from requests.exceptions import InvalidHeader
from requests.exceptions import InvalidProxyURL
from requests.exceptions import StreamConsumedError
from requests.exceptions import JSONDecodeError

from requests import __version__ as requests_version


class Resource:
    """
    class for adding to a class both an internal variable, and a fluent accessor function to set and get such variable.
    """

    def __init__(self, value):
        self._resource = value
        if value.endswith('_'):
            self._variable = value[:-1]
        else:
            self._variable = '_' + value
        self._initial_value = None
        self._get = True
        self._set = True


    def variable(self, value):
        self._variable = value
        return self

    def initial_value(self, value):
        self._initial_value = value
        return self

    def remove_get(self):
        self._get = False

    def remove_set(self):
        self._set = False

    def add_to(self, instance):
        if self._get and self._set:
            self._add_resource(0, instance)
        elif self._set:
            self._add_resource(1, instance)
        else:
            self._add_resource(-1, instance)

    def _add_resource(self, access, instance):
        def add_fn(attr_name, parent):
            cls = parent.__class__

            def fn(instance, *args):
                if len(args) != 0:
                    if access < 0:
                        raise AttributeError
                    setattr(instance, self._variable, args[0])
                    return instance
                if access > 0:
                    raise AttributeError
                return getattr(instance, self._variable)

            setattr(cls, self._resource, fn)

        if (self._resource not in dir(self)):
            setattr(instance, self._variable, self._initial_value)
            add_fn(self._resource, instance)


# *************************** classes in Structures section *****************
"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.
"""


class CaseInsensitiveDict(XMutableMapping):  # ./Structures/CaseInsensitiveDict.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self, data=None, **kwargs):
        self._store = XOrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
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
        return XStr().new(dict(self.items()))


class LookupDict(dict):  # ./Structures/LookupDict.py
    def help(self): Help().display(self.__class__.__name__)

    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % self.name

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class Attributes(object):  # ./utils/attributes.py
    current_attrs = []

    def __init__(self):
        self.cls_names = [x[0] for x in inspect.getmembers(sys.modules[__name__], inspect.isclass)]

    def add_obj(self, attr):
        def add_fn(class_name, attr_name, parent):
            cls = parent.__class__
            def fn(a):
                input = getattr(a, attr)
                return globals()[class_name](input)
            setattr(cls, name, fn)
        name = attr + '_obj'
        class_name = attr.capitalize()
        if (class_name in self.cls_names):
            if (name not in dir(self)):
                add_fn(attr.capitalize(), name, self)

    def add_attribute(self, name, value):  # ./utils/attributes.py
        if (name not in dir(self)):
            self.current_attrs.append(name)
        Resource(name + '_').initial_value(value).add_get_and_set_to(self)
        self.add_obj(name)

    def pick_out_inputs(self, kwargs):  # ./utils/attributes.py
        for k, v in kwargs.items():
            if k in self.current_attrs:
                setattr(self, k, v)
        return self


# *************************** classes in StatusCodes section *****************
class StatusCodes:  # ./StatusCodes/status_codes.py
    def help(self):
        Help().display(self.__class__.__name__)

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

    def __init__(self):  # ./StatusCodes/status_codes.py
        if self._codes_dict.__dict__.__len__() > 10:
            return
        for code, titles in self._codes.items():
            for title in titles:
                setattr(self._codes_dict, title, code)
                if not title.startswith(('\\', '/')):
                    setattr(self._codes_dict, title.upper(), code)

    def doc(self, code):  # ./StatusCodes/status_codes.py
        names = ', '.join('``%s``' % n for n in self._codes[code])
        return '* %d: %s' % (code, names)

    def get(self, name):  # ./StatusCodes/status_codes.py
        return self._codes_dict.get(name)


# *************************** classes in Connections section *****************


class Connections:  # ./Connections/connections.py
    def help(self): Help().display(self.__class__.__name__)

    def DEFAULT_XPOOLBLOCK(self):
        return False

    def DEFAULT_XPOOLSIZE(self):
        return 10

    def DEFAULT_RETRIES(self):
        return 0

    def DEFAULT_XPOOL_TIMEOUT(self):
        return None

    def SOCKSProxyManager(self, *args, **kwargs):
        result = XUrllib3().SOCKSProxyManager(*args, **kwargs)
        if not result:
            raise InvalidSchema("Missing dependencies for SOCKS support.")
        return result

class Cert:
    def __init__(self, input):
        Resource('value_').initial_value(input).add_get_and_set_to(self)

    def cert_verify(self, xconn, url, verify):  # ./Connections/HTTPconnections.py
        if url.lower().startswith('https') and verify:

            cert_loc = None

            # Allow self-specified cert location.
            if verify is not True:
                cert_loc = verify

            if not cert_loc:
                cert_loc = Utils().extract_zipped_paths(Utils().DEFAULT_CA_BUNDLE_PATH())

            if not cert_loc or not XOs().path().exists(cert_loc):
                raise IOError("Could not find a suitable TLS CA certificate bundle, "
                              "invalid path: {}".format(cert_loc))

            xconn.cert_reqs = 'CERT_REQUIRED'

            if not XOs().path().isdir(cert_loc):
                xconn.ca_certs = cert_loc
            else:
                xconn.ca_cert_dir = cert_loc
        else:
            xconn.cert_reqs = 'CERT_NONE'
            xconn.ca_certs = None
            xconn.ca_cert_dir = None

        cert = self.value_()
        if cert:
            if not XBaseString().is_instance(cert):
                xconn.cert_file = cert[0]
                xconn.key_file = cert[1]
            else:
                xconn.cert_file = cert
                xconn.key_file = None
            if xconn.cert_file and not XOs().path().exists(xconn.cert_file):
                raise IOError("Could not find the TLS certificate file, "
                              "invalid path: {}".format(xconn.cert_file))
            if xconn.key_file and not XOs().path().exists(xconn.key_file):
                raise IOError("Could not find the TLS key file, "
                              "invalid path: {}".format(xconn.key_file))


class BaseConnections(object):  # ./Connections/BaseConnections.py
    def help(self): Help().display(self.__class__.__name__)

    """The Base Transport Connection"""

    def __init__(self):  # ./Connections/BaseConnections.py
        super(BaseConnections, self).__init__()

    def send(self, request, stream=False, timeout=None, verify=True,
             cert=None, proxies=None):  # ./Connections/BaseConnections.py
        raise NotImplementedError

    def close(self):  # ./Connections/BaseConnections.py
        """Cleans up adapter specific items."""
        raise NotImplementedError


class Pickler:
    def __getstate__(self):  # ./Connections/HTTPconnections.py
        pickler = eval(self.__class__.__name__ + 'Pickle(self)')
        return pickler.state_()

    def __setstate__(self, state):  # ./Connections/HTTPconnections.py
        pickler = eval(self.__class__.__name__ + 'Pickle(self)')
        return pickler.state_(state)


class HTTPconnections(BaseConnections, Pickler):  # ./Connections/HTTPconnections.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self, xpool_connections=Connections().DEFAULT_XPOOLSIZE(),
                 pool_maxsize=Connections().DEFAULT_XPOOLSIZE(), max_retries=Connections().DEFAULT_RETRIES(),
                 pool_block=Connections().DEFAULT_XPOOLBLOCK()):  # ./Connections/HTTPconnections.py
        if max_retries == Connections().DEFAULT_RETRIES():
            self.max_retries = XUrllib3().util().retry.Retry(0, read=False)
        else:
            self.max_retries = XUrllib3().util().retry.Retry.from_int(max_retries)
        self.config = {}
        self.proxy_manager = {}

        super(HTTPconnections, self).__init__()

        self._xpool_connections = xpool_connections
        self._xpool_maxsize = pool_maxsize
        self._xpool_block = pool_block

        self.init_xpoolmanager(xpool_connections, pool_maxsize, block=pool_block)

    def init_xpoolmanager(self, xconnections, maxsize, block=Connections().DEFAULT_XPOOLBLOCK(), **pool_kwargs):
        # ./Connections/HTTPconnections.py
        # save these values for pickling
        self._xpool_connections = xconnections
        self._xpool_maxsize = maxsize
        self._xpool_block = block

        self.xpoolmanager = XUrllib3().xpoolmanager().PoolManager(num_pools=xconnections, maxsize=maxsize,
                                                                  block=block, strict=True, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):  # ./Connections/HTTPconnections.py
        if proxy in self.proxy_manager:
            manager = self.proxy_manager[proxy]
        elif proxy.lower().startswith('socks'):
            username, password = Url(proxy).get_auth()
            manager = self.proxy_manager[proxy] = XUrllib3().SOCKSProxyManager(
                proxy,
                username=username,
                password=password,
                num_pools=self._xpool_connections,
                maxsize=self._xpool_maxsize,
                block=self._xpool_block,
                **proxy_kwargs
            )
        else:
            proxy_headers = self.proxy_headers(proxy)
            manager = self.proxy_manager[proxy] = XUrllib3().xpoolmanager().proxy_from_url(
                proxy,
                proxy_headers=proxy_headers,
                num_pools=self._xpool_connections,
                maxsize=self._xpool_maxsize,
                block=self._xpool_block,
                **proxy_kwargs)

        return manager

    def build_response(self, req, resp):  # ./Connections/HTTPconnections.py
        response = Response()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code_(getattr(resp, 'status', None))

        # Make headers case-insensitive.
        response.headers_(CaseInsensitiveDict(getattr(resp, 'headers', {})))

        # Set encoding.
        response.encoding_(response.headers_obj().get_encoding_from_headers())
        response.raw_(resp)
        response.reason_(response.raw_().reason)

        if isinstance(req.url_(), bytes):
            response.url_(req.url_().decode('utf-8'))
        else:
            response.url_(req.url_())

        # Add new cookies from the server.
        CookieUtils().to_jar(response.cookies_(), req, resp)

        # Give the Response some context.
        response.request_(req)
        response.xconnection = self

        return response

    def get_connection(self, url, proxies=None):  # ./Connections/HTTPconnections.py
        proxy = Proxies(proxies).select_proxy(url)

        if proxy:
            proxy = Url(proxy).prepend_scheme_if_needed('http')
            proxy_url = XUrllib3().util().parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL("Please check proxy URL. It is malformed"
                                      " and could be missing the host.")
            proxy_manager = self.proxy_manager_for(proxy)
            xconn = proxy_manager.connection_from_url(url)
        else:
            # Only scheme should be lower case
            parsed = Url(url).parse()
            url = parsed.geturl()
            xconn = self.xpoolmanager.connection_from_url(url)

        return xconn

    def close(self):  # ./Connections/HTTPconnections.py
        self.xpoolmanager.clear()
        for proxy in self.proxy_manager.values():
            proxy.clear()

    def request_url(self, request, proxies):  # ./Connections/HTTPconnections.py
        proxy = Proxies(proxies).select_proxy(request.url_())
        scheme = request.url_obj().parse().scheme

        is_proxied_http_request = (proxy and scheme != 'https')
        using_socks_proxy = False
        if proxy:
            proxy_scheme = Url(proxy).parse().scheme.lower()
            using_socks_proxy = proxy_scheme.startswith('socks')

        url = request.path_url_()
        if is_proxied_http_request and not using_socks_proxy:
            url = request.url_obj().defragauth()

        return url

    def add_headers(self, request, **kwargs):  # ./Connections/HTTPconnections.py
        pass

    def proxy_headers(self, proxy):  # ./Connections/HTTPconnections.py
        headers = {}
        username, password = Url(proxy).get_auth()

        if username:
            headers['Proxy-Authorization'] = Auth().basic_auth_str(username,
                                                                   password)

        return headers

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        # ./Connections/HTTPconnections.py
        try:
            xconn = self.get_connection(request.url_(), proxies)
        except XUrllib3().exceptions().LocationValueError as e:
            raise InvalidURL(e, request=request)

        Cert(cert).cert_verify(xconn, request.url_(), verify)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)

        chunked = not (request.body_() is None or 'Content-Length' in request.headers_())

        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = XUrllib3().util().Timeout(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, XUrllib3().util().Timeout):
            pass
        else:
            timeout = XUrllib3().util().Timeout(connect=timeout, read=timeout)

        try:
            if not chunked:
                resp = xconn.urlopen(
                    method=request.method_(),
                    url=url,
                    body=request.body_(),
                    headers=request.headers_(),
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

            # Send the request.
            else:
                if hasattr(xconn, 'proxy_pool'):
                    xconn = xconn.proxy_pool

                low_conn = xconn._get_conn(timeout=Connections().DEFAULT_XPOOL_TIMEOUT())

                try:
                    skip_host = 'Host' in request.headers_()
                    low_conn.putrequest(request.method_(),
                                        url,
                                        skip_accept_encoding=True,
                                        skip_host=skip_host)

                    for header, value in request.headers_().items():
                        low_conn.putheader(header, value)

                    low_conn.endheaders()

                    for i in request.body_():
                        low_conn.send(hex(len(i))[2:].encode('utf-8'))
                        low_conn.send(b'\r\n')
                        low_conn.send(i)
                        low_conn.send(b'\r\n')
                    low_conn.send(b'0\r\n\r\n')

                    # Receive the response from the server
                    try:
                        # For Python 2.7, use buffering of HTTP responses
                        r = low_conn.getresponse(buffering=True)
                    except TypeError:
                        # For compatibility with Python 3.3+
                        r = low_conn.getresponse()

                    resp = XUrllib3().response().HTTPResponse.from_httplib(
                        r,
                        pool=xconn,
                        connection=low_conn,
                        preload_content=False,
                        decode_content=False
                    )
                except Exception as e:
                    # If we hit any problems here, clean up the connection.
                    # Then, reraise so that we can handle the actual exception.
                    low_conn.close()
                    raise e

        except (XUrllib3().exceptions().ProtocolError, XSocket().error()) as err:
            raise ConnectionError(err, request=request)

        except XUrllib3().exceptions().MaxRetryError as e:
            Reason(e.reason).raise_exception(e, request)

        except XUrllib3().exceptions().ClosedPoolError as e:
            raise ConnectionError(e, request=request)

        except XUrllib3().exceptions().ProxyError as e:
            raise ProxyError(e)

        except (XUrllib3().exceptions().SSLError, XUrllib3().exceptions().HTTPError) as e:
            if isinstance(e, XUrllib3().exceptions().SSLError):
                # This branch is for urllib3 versions earlier than v1.22
                raise SSLError(e, request=request)
            elif isinstance(e, XUrllib3().exceptions().ReadTimeoutError):
                raise ReadTimeout(e, request=request)
            elif isinstance(e, XUrllib3().exceptions().InvalidHeader):
                raise InvalidHeader(e, request=request)
            else:
                raise

        return self.build_response(request, resp)


class HTTPconnectionsPickle:  # ./models/Connections/HTTPconnectionsPickle.py
    def __init__(self, instance):
        self.instance = instance

    def state_(self, *args):
        it = self.instance
        if len(args) == 0:
            attrs = ['max_retries', 'config', '_xpool_connections', '_xpool_maxsize',
                     '_xpool_block']
            return {attr: getattr(it, attr, None) for attr in attrs}
        else:
            it.proxy_manager = {}
            it.config = {}

            for attr, value in args[0].items():
                setattr(it, attr, value)

            it.init_xpoolmanager(it._xpool_connections, it._xpool_maxsize,
                                 block=it._xpool_block)


# *************************** classes in Api section *****************
class Requests(Attributes):  # ./Api/api.py
    def help(self): Help().display(self.__class__.__name__)

    def __init__(self):
        super(Requests, self).__init__()
        self.add_attribute('url', None)
        self.add_attribute('data', None)
        self.add_attribute('json', None)
        self.add_attribute('params', None)

    def request(self, method, url, **kwargs):  # ./Api/api.py
        with Sessions().session() as session:
            return session.request(method, url, **kwargs)

    def get(self, **kwargs):  # ./Api/api.py
        return self.request('get', self.url_(), params=self.params_(), **kwargs)

    def options(self, **kwargs):  # ./Api/api.py
        return self.request('options', self.url_(), **kwargs)

    def head(self, **kwargs):  # ./Api/api.py
        kwargs.setdefault('allow_redirects', False)
        return self.request('head', self.url_(), **kwargs)

    def post(self, **kwargs):  # ./Api/api.py
        return self.request('post', self.url_(), **kwargs)

    def put(self, **kwargs):  # ./Api/api.py
        return self.request('put', self.url_(), data=self.data_(), **kwargs)

    def patch(self, **kwargs):  # ./Api/api.py
        return self.request('patch', self.url_(), data=self.data_(), **kwargs)

    def delete(self, **kwargs):  # ./Api/api.py
        return self.request('delete', self.url_(), **kwargs)


# *************************** classes in Auth section *****************
class Auth:  # ./Auth/auth.py
    def __init__(self, input=None):
        Resource('value_').initial_value(input).add_get_and_set_to(self)

    def help(self):
        Help().display(self.__class__.__name__)

    CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
    CONTENT_TYPE_MULTI_PART = 'multipart/form-data'

    def prepare(self, request):  # ./Auth/auth.py
        auth = self.value_()
        if auth is None:
            url_auth = request.url_obj().get_auth()
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                # special-case basic HTTP auth
                auth = HTTPBasicAuth(*auth)

            # Allow auth to make its changes.
            r = auth(request)

            # Update self to reflect the auth changes.
            self.__dict__.update(r.__dict__)

            # Recompute Content-Length
            request.headers_().update(Body(request).prepare_content_length().headers())
        self.value_(auth)
        return self.value_()

    def basic_auth_str(self, username, password):  # ./Auth/auth.py
        if not XBaseString().is_instance(username):
            XWarnings().warn((
                "Non-string usernames will no longer be supported in Requests "
                "3.0.0. Please convert the object you've passed in ({!r}) to "
                "a string or bytes object in the near future to avoid "
                "problems.".format(username)),
                category=DeprecationWarning,
            )
            username = XStr().new(username)

        if not XBaseString().is_instance(password):
            XWarnings().warn((
                "Non-string passwords will no longer be supported in Requests "
                "3.0.0. Please convert the object you've passed in ({!r}) to "
                "a string or bytes object in the near future to avoid "
                "problems.".format(type(password))),
                category=DeprecationWarning,
            )
            password = XStr().new(password)
        # -- End Removal --

        if XStr().is_instance(username):
            username = username.encode('latin1')

        if XStr().is_instance(password):
            password = password.encode('latin1')

        authstr = 'Basic ' + XUtils().to_native_string(
            XBase64().b64encode(b':'.join((username, password))).strip()
        )

        return authstr


class AuthBase:  # ./Auth/AuthBase.py
    def help(self): Help().display(self.__class__.__name__)

    def __call__(self, r):  # ./Auth/AuthBase.py
        raise NotImplementedError('Auth hooks must be callable.')


class HTTPBasicAuth(AuthBase):  # ./Auth/HTTPBasicAuth.py
    def help(self): Help().display(self.__class__.__name__)

    def __init__(self, username, password):  # ./Auth/HTTPBasicAuth.py
        self.username = username
        self.password = password

    def __eq__(self, other):  # ./Auth/HTTPBasicAuth.py
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):  # ./Auth/HTTPBasicAuth.py
        return not self == other

    def __call__(self, r):  # ./Auth/HTTPBasicAuth.py
        r.headers_()['Authorization'] = Auth().basic_auth_str(self.username, self.password)
        return r


class HTTPProxyAuth(HTTPBasicAuth):  # ./Auth/HTTPProxyAuth.py
    def help(self): Help().display(self.__class__.__name__)

    def __call__(self, r):
        r.headers_()['Proxy-Authorization'] = Auth().basic_auth_str(self.username, self.password)
        return r


class HTTPDigestAuth(AuthBase):  # ./Auth/HTTPDigestAuth.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self, username, password):  # ./Auth/HTTPDigestAuth.py
        self.username = username
        self.password = password
        # Keep state in per-thread local storage
        self._thread_local = XThreading().local()

    def init_per_thread_state(self):  # ./Auth/HTTPDigestAuth.py
        # Ensure state is initialized just once per-thread
        if not hasattr(self._thread_local, 'init'):
            self._thread_local.init = True
            self._thread_local.last_nonce = ''
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    def build_digest_header(self, method, url):  # ./Auth/HTTPDigestAuth.py
        """
        :rtype: XStr().clazz()
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
                if XStr().is_instance(x):
                    x = x.encode('utf-8')
                return XHashLib().md5(x).hexdigest()

            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if XStr().is_instance(x):
                    x = x.encode('utf-8')
                return XHashLib().sha1(x).hexdigest()

            hash_utf8 = sha_utf8
        elif _algorithm == 'SHA-256':
            def sha256_utf8(x):
                if XStr().is_instance(x):
                    x = x.encode('utf-8')
                return XHashLib().sha256(x).hexdigest()

            hash_utf8 = sha256_utf8
        elif _algorithm == 'SHA-512':
            def sha512_utf8(x):
                if XStr().is_instance(x):
                    x = x.encode('utf-8')
                return XHashLib().sha512(x).hexdigest()

            hash_utf8 = sha512_utf8

        def KD(s, d):
            return hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = Url(url).parse()
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
        s = XStr().new(self._thread_local.nonce_count).encode('utf-8')
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

        return 'Digest %s' % base

    def handle_redirect(self, r, **kwargs):  # ./Auth/HTTPDigestAuth.py
        """Reset num_401_calls counter on redirects."""
        if r.is_redirect_():
            self._thread_local.num_401_calls = 1

    def handle_401(self, r, **kwargs):  # ./Auth/HTTPDigestAuth.py
        """
        Takes the given response and tries digest-auth, if needed.

        :rtype: requests.Response
        """

        # If response is not 4xx, do not auth
        # See https://github.com/psf/requests/issues/3772
        if not 400 <= r.status_code_() < 500:
            self._thread_local.num_401_calls = 1
            return r

        if self._thread_local.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request_().body().seek(self._thread_local.pos)
        s_auth = r.headers_().get('www-authenticate', '')

        if 'digest' in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = XRe().compile(r'digest ', flags=XRe().IGNORECASE())
            self._thread_local.chal = WSGIutils().parse_dict_header(pat.sub('', s_auth, count=1))

            # Consume content and release the original xconnection
            # to allow our new request to reuse the same one.
            r.content_()
            r.close()
            prep = r.request_().copy()
            CookieUtils().to_jar(prep.cookies_(), r.request_(), r.raw_())
            prep.prepare_cookies(prep.cookies_())

            prep.headers_()['Authorization'] = self.build_digest_header(
                prep.method_(), prep.url_())
            _r = r.xconnection.send(prep, **kwargs)
            _r.history_().append(r)
            _r.request_(prep)

            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):  # ./Auth/HTTPDigestAuth.py
        # Initialize per-thread state, if needed
        self.init_per_thread_state()
        # If we have a saved nonce, skip the 401
        if self._thread_local.last_nonce:
            r.headers_()['Authorization'] = self.build_digest_header(r.method_(), r.url_())
        try:
            self._thread_local.pos = r.body_().tell()
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

    def __eq__(self, other):  # ./Auth/HTTPDigestAuth.py
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):  # ./Auth/HTTPDigestAuth.py
        return not self == other


# *************************** classes in Certs section *****************
class Certs:  # ./Certs/Certs.py
    def help(self): Help().display(self.__class__.__name__)

    def where(self):
        return certifi_where()


# *************************** classes in Cookies section *****************
class CookieUtils:  # ./cookies/CookieUtils.py
    def help(self):
        Help().display(self.__class__.__name__)

    def to_jar(self, jar, request, response):
        if not (hasattr(response, '_original_response') and
                response._original_response):
            return
        # the _original_response field is the wrapped httplib.HTTPResponse object,
        req = XCookieJarRequest(request)
        # pull out the HTTPMessage with the headers and put it in the mock:
        res = XCookieJarResponse(response._original_response.msg)
        jar.extract_cookies(res, req)

    def get_cookie_header(self, jar, request):  # ./cookies/CookieUtils.py
        r = XCookieJarRequest(request)
        jar.add_cookie_header(r)
        return r.added_headers().get('Cookie')

    def remove_cookie_by_name(self, cookiejar, name, domain=None, path=None):  # ./cookies/CookieUtils.py
        """Unsets a cookie by name, by default over all domains and paths.

        Wraps CookieJar.clear() (CookieJar or XCookieJar), is O(n).
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

    def _copy_cookie_jar(self, jar):  # ./cookies/CookieUtils.py
        if jar is None:
            return None

        if hasattr(jar, 'copy'):
            # We're dealing with an instance of CookieJar
            return jar.copy()
        # We're dealing with a XCookieJar instance
        new_jar = XCopy().copy(jar)
        new_jar.clear()
        for cookie in jar:
            new_jar.set_cookie(XCopy().copy(cookie))
        return new_jar

    def create_cookie(self, name, value, **kwargs):  # ./cookies/CookieUtils.py
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

        return XCookie(**result)

    def morsel_to_cookie(self, morsel):  # ./cookies/CookieUtils.py
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

    def cookiejar_from_dict(self, cookie_dict, cookiejar=None, overwrite=True):  # ./cookies/CookieUtils.py
        if cookiejar is None:
            cookiejar = CookieJar()

        if cookie_dict is not None:
            names_from_jar = [cookie.name for cookie in cookiejar]
            for name in cookie_dict:
                if overwrite or (name not in names_from_jar):
                    cookiejar.set_cookie(self.create_cookie(name, cookie_dict[name]))

        return cookiejar

    def merge_cookies(self, cookiejar, cookies):  # ./cookies/CookieUtils.py
        if not isinstance(cookiejar, XCookieJar):
            raise ValueError('You can only merge into CookieJar')

        if isinstance(cookies, dict):
            cookiejar = self.cookiejar_from_dict(
                cookies, cookiejar=cookiejar, overwrite=False)
        elif isinstance(cookies, XCookieJar):
            try:
                cookiejar.update(cookies)
            except AttributeError:
                for cookie_in_jar in cookies:
                    cookiejar.set_cookie(cookie_in_jar)

        return cookiejar

    def dict_from_cookiejar(self, cj):  # ./cookies/CookieUtils.py
        cookie_dict = {}

        for cookie in cj:
            cookie_dict[cookie.name] = cookie.value

        return cookie_dict

    def add_dict_to_cookiejar(self, cj, cookie_dict):  # ./cookies/CookieUtils.py
        return self.cookiejar_from_dict(cookie_dict, cj)


class CookieConflictError(RuntimeError):  # ./cookies/CookieConflictError.py
    def help(self): Help().display(self.__class__.__name__)


class CookieJar(XCookieJar, XMutableMapping, Pickler):  # ./cookies/cookie_jar.py
    def help(self):
        Help().display(self.__class__.__name__)

    def get(self, name, default=None, domain=None, path=None):  # ./cookies/cookie_jar.py
        """Dict-like get() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.

        .. warning:: operation is O(n), not O(1).
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):  # ./cookies/cookie_jar.py
        """Dict-like set() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.
        """
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            CookieUtils().remove_cookie_by_name(self, name, domain=kwargs.get('domain'), path=kwargs.get('path'))
            return

        if isinstance(value, XMorsel):
            c = self.morsel_to_cookie(value)
        else:
            c = CookieUtils().create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self):  # ./cookies/cookie_jar.py
        """Dict-like iterkeys() that returns an iterator of names of cookies
        from the jar.

        .. seealso:: itervalues() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self):  # ./cookies/cookie_jar.py
        """Dict-like keys() that returns a list of names of cookies from the
        jar.

        .. seealso:: values() and items().
        """
        return list(self.iterkeys())

    def itervalues(self):  # ./cookies/cookie_jar.py
        """Dict-like itervalues() that returns an iterator of values of cookies
        from the jar.

        .. seealso:: iterkeys() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self):  # ./cookies/cookie_jar.py
        """Dict-like values() that returns a list of values of cookies from the
        jar.

        .. seealso:: keys() and items().
        """
        return list(self.itervalues())

    def iteritems(self):  # ./cookies/cookie_jar.py
        """Dict-like iteritems() that returns an iterator of name-value tuples
        from the jar.

        .. seealso:: iterkeys() and itervalues().
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self):  # ./cookies/cookie_jar.py
        """Dict-like items() that returns a list of name-value tuples from the
        jar. Allows client-code to call ``dict(CookieJar)`` and get a
        vanilla python dict of key value pairs.

        .. seealso:: keys() and values().
        """
        return list(self.iteritems())

    def list_domains(self):  # ./cookies/cookie_jar.py
        """Utility method to list all the domains in the jar."""
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self):  # ./cookies/cookie_jar.py
        """Utility method to list all the paths in the jar."""
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self):  # ./cookies/cookie_jar.py
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

    def get_dict(self, domain=None, path=None):  # ./cookies/cookie_jar.py
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

    def __contains__(self, name):  # ./cookies/cookie_jar.py
        try:
            return super(CookieJar, self).__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name):  # ./cookies/cookie_jar.py
        """Dict-like __getitem__() for compatibility with client code. Throws
        exception if there are more than one cookie with name. In that case,
        use the more explicit get() method instead.

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name, value):  # ./cookies/cookie_jar.py
        """Dict-like __setitem__ for compatibility with client code. Throws
        exception if there is already a cookie of that name in the jar. In that
        case, use the more explicit set() method instead.
        """
        self.set(name, value)

    def __delitem__(self, name):  # ./cookies/cookie_jar.py
        """Deletes a cookie given a name. Wraps ``cookielib.CookieJar``'s
        ``remove_cookie_by_name()``.
        """
        CookieUtils().remove_cookie_by_name(self, name)

    def set_cookie(self, cookie):  # ./cookies/cookie_jar.py
        if hasattr(cookie.value, 'startswith') and cookie.value.startswith('"') and cookie.value.endswith('"'):
            cookie.value = cookie.value.replace('\\"', '')
        return super(CookieJar, self).set_cookie(cookie)

    def update(self, other):  # ./cookies/cookie_jar.py
        """Updates this jar with cookies from another CookieJar (CookieJar or XCookieJar) or dict-like"""
        if isinstance(other, XCookieJar):
            for cookie in other:
                self.set_cookie(XCopy().copy(cookie))
        else:
            super(CookieJar, self).update(other)

    def _find(self, name, domain=None, path=None):  # ./cookies/cookie_jar.py
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

    def _find_no_duplicates(self, name, domain=None, path=None):  # ./cookies/cookie_jar.py
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
                            raise CookieConflictError('There are multiple cookies with name, %r' % name)
                        toReturn = cookie.value  # we will eventually return this as long as no cookie conflict

        if toReturn:
            return toReturn
        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

    def copy(self):  # ./cookies/cookie_jar.py
        """Return a copy of this CookieJar."""
        new_cj = CookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self):  # ./cookies/cookie_jar.py
        """Return the CookiePolicy instance used."""
        return self._policy


class CookieJarPickle:  # ./cookies/cookie_jar_pickle.py
    def __init__(self, instance):
        self.instance = instance

    def state_(self, *args):
        it = self.instance
        if len(args) == 0:
            """Unlike a XCookieJar, this class is picklable."""
            state = it.__dict__.copy()
            # remove the unpicklable RLock object
            state.pop('_cookies_lock')
            return state
        else:
            """Unlike a XCookieJar, this class is picklable."""
            it.__dict__.update(args[0])
            if '_cookies_lock' not in self.__dict__:
                it._cookies_lock = XThreading().RLock()


# *************************** classes in Help section *****************

class Info:  # ./Help/info.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self):  # ./Help/info.py
        pass

    def _implementation(self):  # ./Help/info.py
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

    def info(self):  # ./Help/info.py
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
        if XCharDet('help.py').import_works():
            chardet_info = {'version': XCharDet('help.py').version()}

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
            'version': XCryptography().version(),
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
            'using_charset_normalizer': XCharDet('help.py').import_works(),
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


# *************************** classes in Hooks section *****************

class Hooks:  # ./Hooks/hooks.py
    def help(self):
        Help().display(self.__class__.__name__)

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


# *************************** classes in Models section *****************

class Models:  # ./models/models.py
    def help(self): Help().display(self.__class__.__name__)

    _REDIRECT_STATI = (
        StatusCodes().get('moved'),  # 301
        StatusCodes().get('found'),  # 302
        StatusCodes().get('other'),  # 303
        StatusCodes().get('temporary_redirect'),  # 307
        StatusCodes().get('permanent_redirect'),  # 308
    )

    _DEFAULT_REDIRECT_LIMIT = 30
    _CONTENT_CHUNK_SIZE = 10 * 1024
    _ITER_CHUNK_SIZE = 512

    def REDIRECT_STATI(self):
        return self._REDIRECT_STATI

    def DEFAULT_REDIRECT_LIMIT(self):
        return self._DEFAULT_REDIRECT_LIMIT

    def CONTENT_CHUNK_SIZE(self):
        return self._CONTENT_CHUNK_SIZE

    def ITER_CHUNK_SIZE(self):
        return self._ITER_CHUNK_SIZE


class Encoding:  # ./models/Encoding.py
    def help(self):
        Help().display(self.__class__.__name__)

    def path_url(self, url_in):  # ./models/Encoding.py

        url = []

        p = Url(url_in).split()

        path = p.path
        if not path:
            path = '/'

        url.append(path)

        query = p.query
        if query:
            url.append('?')
            url.append(query)

        return ''.join(url)

    def params(self, data):  # ./models/Encoding.py
        if isinstance(data, (XStr().clazz(), XBytes().clazz())):
            return data
        elif hasattr(data, 'read'):
            return data
        elif hasattr(data, '__iter__'):
            result = []
            for k, vs in CollectionsUtils().to_key_val_list(data):
                if XBaseString().is_instance(vs) or not hasattr(vs, '__iter__'):
                    vs = [vs]
                for v in vs:
                    if v is not None:
                        result.append(
                            (k.encode('utf-8') if XStr().is_instance(k) else k,
                             v.encode('utf-8') if XStr().is_instance(v) else v))
            return XUrl().encode(result, doseq=True)
        else:
            return data

    def files(self, files, data):  # ./models/Encoding.py
        if not files:
            raise ValueError("Files must be provided.")
        elif XBaseString().is_instance(data):
            raise ValueError("Data must not be a string.")

        new_fields = []
        fields = CollectionsUtils().to_key_val_list(data or {})
        files = CollectionsUtils().to_key_val_list(files or {})

        for field, val in fields:
            if XBaseString().is_instance(val) or not hasattr(val, '__iter__'):
                val = [val]
            for v in val:
                if v is not None:
                    # Don't call str() on bytestrings: in Py3 it all goes wrong.
                    if not XBytes().is_instance(v):
                        v = XStr().new(v)

                    new_fields.append(
                        (field.decode('utf-8') if XBytes().is_instance(field) else field,
                         v.encode('utf-8') if XStr().is_instance(v) else v))

        for (k, v) in files:
            # support for explicit filename
            ft = None
            fh = None
            if isinstance(v, (tuple, list)):
                if len(v) == 2:
                    fn, fp = v
                elif len(v) == 3:
                    fn, fp, ft = v
                else:
                    fn, fp, ft, fh = v
            else:
                fn = FileUtils().guess_filename(v) or k
                fp = v

            if isinstance(fp, (XStr().clazz(), XBytes().clazz(), bytearray)):
                fdata = fp
            elif hasattr(fp, 'read'):
                fdata = fp.read()
            elif fp is None:
                continue
            else:
                fdata = fp

            rf = XUrllib3().fields().RequestField(name=k, data=fdata, filename=fn, headers=fh)
            rf.make_multipart(content_type=ft)
            new_fields.append(rf)

        body, content_type = XUrllib3().filepost().encode_multipart_formdata(new_fields)

        return body, content_type


class RequestHooks:  # ./models/RequestHooks.py
    def help(self):
        Help().display(self.__class__.__name__)

    def register_hook(self, event, hook):
        if event not in self.hooks_():
            raise ValueError('Unsupported event specified, with event name "%s"' % event)

        XCompat().append_callable_instance(self.hooks_()[event], hook)

    def deregister_hook(self, event, hook):
        try:
            self.hooks_()[event].remove(hook)
            return True
        except ValueError:
            return False


class CommonProperties(Attributes):
    def __init__(self):  # ./models/Request.py
        super(CommonProperties, self).__init__()
        self.add_attribute('cookies', None)
        self.add_attribute('headers', {})
        self.add_attribute('url', None)


class Request(CommonProperties, RequestHooks, Attributes):  # ./models/Request.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self):  # ./models/Request.py
        super(Request, self).__init__()
        self.add_attribute('auth', None)
        self.add_attribute('data', [])
        self.add_attribute('files', [])
        self.add_attribute('json', None)
        self.add_attribute('method', None)
        self.add_attribute('params', None)

        self.auth = None
        self.hooks = Hooks().default_hooks()

    def __repr__(self):  # ./models/Request.py
        return '<Request [%s]>' % (self.method_())

    def prepare(self):  # ./models/Request.py
        """Constructs a :class:`PreparedRequest <PreparedRequest>` for transmission and returns it."""
        return Ticket() \
            .method_(self.method_()) \
            .url_(self.url_()) \
            .headers_(self.headers_()) \
            .files_(self.files_()) \
            .data_(self.data_()) \
            .json_(self.json_()) \
            .params_(self.params_()) \
            .auth_(self.auth_()) \
            .cookies_(self.cookies_()) \
            .hooks_(self.hooks_()) \
            .prepare()

    def add_header(self, key, value):  # ./models/Request.py
        self.headers_()[key] = value
        return self

    def path_url_(self):
        return Encoding().path_url(self.url_())

    def hooks_(self, *args):  # ./models/Request.py
        if len(args) != 0:
            self.hooks = Hooks().default_hooks()
            hooks = args[0] if args[0] else {}
            for (k, v) in list(hooks.items()):
                self.register_hook(event=k, hook=v)
            return self
        else:
            return self.hooks


class Method:  # ./models/method.py
    def __init__(self, input):
        Resource('value_').initial_value(input).add_get_and_set_to(self)

    def prepare(self):  # ./models/method.py
        """Prepares the given HTTP method."""
        if self.value_() is not None:
            self.value_(XUtils().to_native_string(self.value_().upper()))
        return self.value_()

    def rebuild(self, status_code):
        # https://tools.ietf.org/html/rfc7231#section-6.4.4
        if status_code == StatusCodes().get('see_other') and self.value_() != 'HEAD':
            self.value_('GET')

        # Do what the browsers do, despite standards...
        # First, turn 302s into GETs.
        if status_code == StatusCodes().get('found') and self.value_() != 'HEAD':
            self.value_('GET')

        # Second, if a POST is responded to with a 301, turn it into a GET.
        # This bizarre behaviour is explained in Issue 1704.
        if status_code == StatusCodes().get('moved') and self.value_() == 'POST':
            self.value_('GET')
        return self.value_()


class Cookies:  # ./models/cookies.py
    def __init__(self, cookies):
        self.cookies_(cookies)

    def prepare(self, request):  # ./models/cookies.py
        cookies = self.cookies_()
        if isinstance(cookies, XCookieJar):
            self.cookies_(cookies)
        else:
            self.cookies_(CookieUtils().cookiejar_from_dict(cookies))

        self.cookie_header = CookieUtils().get_cookie_header(self.cookies_(), request)

        return self.cookies_()

    def cookies_(self, *args):  # ./models/cookies.py
        return DomainUtils().get_or_set(self, 'cookies', *args)

    def cookie_header_(self):  # ./models/cookies.py
        return self.cookie_header


class Headers:  # ./models/headers.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self, headers=None):  # ./models/headers.py
        Resource('value_').initial_value(headers).add_get_and_set_to(self)

    def prepare(self):  # ./models/headers.py
        """Prepares the given HTTP headers."""
        headers = self.value_()
        self.value_(CaseInsensitiveDict())
        if headers:
            for header in headers.items():
                # Raise exception on invalid header value.
                Header().check_header_validity(header)
                name, value = header
                self.value_()[XUtils().to_native_string(name)] = value
        return self.value_()

    def get_encoding_from_headers(self):  # ./models/headers.py
        content_type = self.value_().get('content-type')

        if not content_type:
            return None

        content_type, params = Header()._parse_content_type_header(content_type)

        if 'charset' in params:
            return params['charset'].strip("'\"")

        if 'text' in content_type:
            return 'ISO-8859-1'

        if 'application/json' in content_type:
            # Assume UTF-8 based on RFC 4627: https://www.ietf.org/rfc/rfc4627.txt since the charset was unset
            return 'utf-8'

    def default_headers(self):  # ./Utils/headers.py
        return CaseInsensitiveDict({
            'User-Agent': Header().default_user_agent(),
            'Accept-Encoding': Header().DEFAULT_ACCEPT_ENCODING(),
            'Accept': '*/*',
            'Connection': 'keep-alive',
        })


class Header:  # ./models/header.py
    # Ensure that ', ' is used to preserve previous delimiter behavior.
    _DEFAULT_ACCEPT_ENCODING = ", ".join(
        XRe().split(r",\s*", XUrllib3().util().make_headers(accept_encoding=True)["accept-encoding"])
    )

    # Moved outside of function to avoid recompile every call
    _CLEAN_HEADER_REGEX_BYTE = XRe().compile(b'^\\S[^\\r\\n]*$|^$')
    _CLEAN_HEADER_REGEX_STR = XRe().compile(r'^\S[^\r\n]*$|^$')

    def DEFAULT_ACCEPT_ENCODING(self):  # ./Utils/header.py
        return self._DEFAULT_ACCEPT_ENCODING

    def _parse_content_type_header(self, header):  # ./models/header.py
        tokens = header.split(';')
        content_type, params = tokens[0].strip(), tokens[1:]
        params_dict = {}
        items_to_strip = "\"' "

        for param in params:
            param = param.strip()
            if param:
                key, value = param, True
                index_of_equals = param.find("=")
                if index_of_equals != -1:
                    key = param[:index_of_equals].strip(items_to_strip)
                    value = param[index_of_equals + 1:].strip(items_to_strip)
                params_dict[key.lower()] = value
        return content_type, params_dict

    def parse_header_links(self, value):  # ./Utils/header.py
        links = []

        replace_chars = ' \'"'

        value = value.strip(replace_chars)
        if not value:
            return links

        for val in XRe().split(', *<', value):
            try:
                url, params = val.split(';', 1)
            except ValueError:
                url, params = val, ''

            link = {'url': url.strip('<> \'"')}

            for param in params.split(';'):
                try:
                    key, value = param.split('=')
                except ValueError:
                    break

                link[key.strip(replace_chars)] = value.strip(replace_chars)

            links.append(link)

        return links

    def check_header_validity(self, header):  # ./Utils/header.py
        name, value = header

        if XBytes().is_instance(value):
            pat = self._CLEAN_HEADER_REGEX_BYTE
        else:
            pat = self._CLEAN_HEADER_REGEX_STR
        try:
            if not pat.match(value):
                raise InvalidHeader("Invalid return character or leading space in header: %s" % name)
        except TypeError:
            raise InvalidHeader("Value for header {%s: %s} must be of type str or "
                                "bytes, not %s" % (name, value, type(value)))

    def default_user_agent(self, name="python-requests"):  # ./Utils/header.py
        return '%s/%s' % (name, requests_version)


class Ticket(CommonProperties, RequestHooks, Attributes):  # ./models/ticket.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self):  # ./models/ticket.py
        super(Ticket, self).__init__()
        self.add_attribute('method', None)
        self.add_attribute('files', None)
        self.add_attribute('data', None)
        self.add_attribute('params', None)
        self.add_attribute('auth', None)
        self.add_attribute('hooks', Hooks().default_hooks())
        self.add_attribute('json', None)
        self.add_attribute('body', None)
        self._body_position = None  #: integer denoting starting position of a readable file-like body.

    def prepare(self):  # ./models/ticket.py
        """Prepares the entire request with the given parameters."""

        self.method_(self.method_obj().prepare())

        self.url_(self.url_obj().prepare(self.params_()).value_())
        self.headers_(self.headers_obj().prepare())
        self.prepare_cookies(self.cookies_())
        self.prepare_body(self.data_(), self.files_(), self.json_())
        self.auth_obj().prepare(self)

        # Note that prepare_auth must be last to enable authentication schemes
        # such as OAuth to work on a fully prepared request.

        # This MUST go after prepare_auth. Authenticators could add a hook
        self.prepare_hooks(self.hooks_())
        del self.data, self.files, self.json, self.params
        return self

    def __repr__(self):  # ./models/ticket.py
        return '<PreparedRequest [%s]>' % (self.method_())

    def copy(self):  # ./models/ticket.py
        p = Ticket()
        p.method_(self.method_())
        p.url_(self.url_())
        p.headers_(self.headers_().copy() if self.headers_() is not None else None)
        p.cookies_(CookieUtils()._copy_cookie_jar(self.cookies_()))
        p.body_(self.body_())
        p.hooks_(self.hooks_())
        p._body_position = self._body_position
        return p

    @staticmethod
    def _get_idna_encoded_host(host):  # ./models/ticket.py
        try:
            host = XIdna().encode(host, uts46=True).decode('utf-8')
        except XIdna().IDNAError():
            raise UnicodeError
        return host

    def prepare_body(self, data, files, json=None):  # ./models/ticket.py
        body = Body(self)
        self.body_(body.prepare(data, files, json))
        if body.is_stream():
            self._body_position = body.body_position()
        headers = self.headers_()
        headers.update(body.headers())

    def prepare_auth(self, auth):  # ./models/ticket.py
        self.auth_(auth).auth_obj().prepare(self)

    def prepare_cookies(self, cookies):  # ./models/ticket.py
        c = Cookies(cookies)
        self.cookies_(c.prepare(self))
        cookie_header = c.cookie_header_()
        if cookie_header is not None:
            self.headers_()['Cookie'] = cookie_header

    def prepare_hooks(self, hooks):  # ./models/ticket.py
        self.hooks_(Hooks().default_hooks())  #: dictionary of callback hooks, for internal usage.
        hooks = hooks or []
        for event in hooks:
            self.register_hook(event, hooks[event])

    def path_url_(self):
        return Encoding().path_url(self.url_())

class Data:
    def __init__(self, data):
        self.data = data

    def is_stream(self):
        return all([
            hasattr(self.data, '__iter__'),
            not isinstance(self.data, (XBaseString().clazz(), list, tuple, XMapping))
        ])

class Body:  # ./models/body.py
    def __init__(self, request):  # ./models/body.py
        self.request = request
        Resource('body_').initial_value(request.body_()).add_get_and_set_to(self)
        Resource('body_position').add_get_and_set_to(self)
        self._headers = {}

    def prepare(self, data, files, json):  # ./models/body.py
        self.body = None
        content_type = None

        if not data and json is not None:
            # urllib3 requires a bytes-like body. Python 2's json.dumps
            # provides this natively, but Python 3 gives a Unicode string.
            content_type = 'application/json'

            try:
                self.body = complexjson.dumps(json, allow_nan=False)
            except ValueError as ve:
                raise InvalidJSONError(ve, request=self.request)

            if not XBytes().is_instance(self.body):
                self.body = self.body.encode('utf-8')

        self._is_stream = Data(data).is_stream()

        if self._is_stream:
            try:
                length = Utils().super_len(data)
            except (TypeError, AttributeError, XIo().UnsupportedOperation()):
                length = None

            self.body = data

            if getattr(self.body, 'tell', None) is not None:
                # Record the current file position before reading.
                # This will allow us to rewind a file in the event
                # of a redirect.
                try:
                    self._body_position = self.body.tell()
                except (IOError, OSError):
                    # This differentiates from None, allowing us to catch
                    # a failed `tell()` later when trying to rewind the body
                    self._body_position = object()

            if files:
                raise NotImplementedError('Streamed bodies and files are mutually exclusive.')

            if length:
                self._headers['Content-Length'] = XBuiltinStr().new(length)
            else:
                self._headers['Transfer-Encoding'] = 'chunked'
        else:
            # Multi-part file uploads.
            if files:
                (self.body, content_type) = Encoding().files(files, data)
            else:
                if data:
                    self.body = Encoding().params(data)
                    if XBaseString().is_instance(data) or hasattr(data, 'read'):
                        content_type = None
                    else:
                        content_type = 'application/x-www-form-urlencoded'

            self.prepare_content_length()

            # Add content-type if it wasn't explicitly provided.
            if content_type and ('content-type' not in self.request.headers_()):
                self._headers['Content-Type'] = content_type
        return self.body

    def prepare_content_length(self):  # ./models/body.py
        if self.body is not None:
            length = Utils().super_len(self.body)
            if length:
                # If length exists, set it. Otherwise, we fallback
                # to Transfer-Encoding: chunked.
                self._headers['Content-Length'] = XBuiltinStr().new(length)
        elif self.request.method_() not in ('GET', 'HEAD') and self.request.headers_().get('Content-Length') is None:
            # Set Content-Length to 0 for methods that can have a body
            # but don't provide one. (i.e. not GET or HEAD)
            self._headers['Content-Length'] = '0'
        return self

    def headers(self):  # ./models/body.py
        return self._headers

    def is_stream(self):  # ./models/body.py
        return self._is_stream


class Content:  # ./models/Content.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self, read_func):  # ./models/Content.py
        Resource('internal_content').variable('_content').initial_value(False).add_get_and_set_to(self)
        self._content_consumed = False
        self._read = read_func

    def check_for_consistency(self, chunk_size):  # ./models/Content.py
        if self._content_consumed and isinstance(self._content, bool):
            raise StreamConsumedError()
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError("chunk_size must be an int, it is instead a %s." % type(chunk_size))

    def iterate(self, chunk_size, decode_unicode, raw, encoding):  # ./models/Content.py
        def generate():  # ./models/Content.py
            # Special case for urllib3.
            if hasattr(raw, 'stream'):
                try:
                    for chunk in raw.stream(chunk_size, decode_content=True):
                        yield chunk
                except XUrllib3().exceptions().ProtocolError as e:
                    raise ChunkedEncodingError(e)
                except XUrllib3().exceptions().DecodeError as e:
                    raise ContentDecodingError(e)
                except XUrllib3().exceptions().ReadTimeoutError as e:
                    raise ConnectionError(e)
            else:
                # Standard file-like object.
                while True:
                    chunk = raw.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            self._content_consumed = True

        self.check_for_consistency(chunk_size)
        # simulate reading small chunks of the content
        reused_chunks = Utils().iter_slices(self._content, chunk_size)

        stream_chunks = generate()

        chunks = reused_chunks if self._content_consumed else stream_chunks

        if decode_unicode:
            chunks = Utils().stream_decode_response_unicode(chunks, encoding)

        return chunks

    def close(self, raw):  # ./models/Content.py
        if not self._content_consumed:
            raw.close()

    def content(self):  # ./models/Content.py
        if self._content is False:
            # Read the contents.
            if self._content_consumed:
                raise RuntimeError(
                    'The content for this response was already consumed')
            self._content = b''
            self._content = self._read()

        self._content_consumed = True
        # don't need to release the xconnection; that's been handled by urllib3
        # since we exhausted the data.
        return self._content

    def consume_everything(self):  # ./models/Content.py
        if not self._content_consumed:
            self.content()

    def apparent_encoding(self):  # ./models/Content.py
        """The apparent encoding, provided by the charset_normalizer or chardet libraries."""
        return XCharDet().detect(self.content())['encoding']

    def text(self, encoding):  # ./models/Content.py
        content = None

        if not self.content():
            return XStr().new('')

        # Fallback to auto-detected encoding.
        if encoding is None:
            encoding = self.apparent_encoding()

        # Decode unicode from given encoding.
        try:
            content = XStr().new(self.content(), encoding, errors='replace')
        except (LookupError, TypeError):
            # A LookupError is raised if the encoding was not found which could
            # indicate a misspelling or similar mistake.
            #
            # A TypeError can be raised if encoding is None
            #
            # So we try blindly encoding.
            content = XStr().new(self.content(), errors='replace')

        return content

    def json(self, encoding, **kwargs):  # ./models/Content.py
        if not encoding and self.content and len(self.content()) > 3:
            # No encoding set. JSON RFC 4627 section 3 states we should expect
            # UTF-8, -16 or -32. Detect which one to use; If the detection or
            # decoding fails, fall back to `self.text` (using charset_normalizer to make
            # a best guess).
            encoding = Utils().guess_json_utf(self.content())
            if encoding is not None:
                try:
                    return complexjson.loads(
                        self.content().decode(encoding), **kwargs
                    )
                except UnicodeDecodeError:
                    # Wrong UTF codec detected; usually because it's not UTF-8
                    # but some other 8-bit codec.  This is an RFC violation,
                    # and the server didn't bother to tell us what codec *was*
                    # used.
                    pass

        try:
            return complexjson.loads(self.text(encoding), **kwargs)
        except XJSONDecodeError as e:
            # Catch JSON-related errors and raise as requests.JSONDecodeError
            # This aliases json.JSONDecodeError and simplejson.JSONDecodeError
            raise JSONDecodeError(e.msg, e.doc, e.pos)

    def reset_content_consumed(self):  # ./models/Content.py
        self._content_consumed = True


class Response(CommonProperties, Pickler, Attributes):  # ./models/Response/Response.py
    def __init__(self):  # ./models/Response.py
        super(Response, self).__init__()
        self.add_attribute('status_code', None)
        self.add_attribute('headers', CaseInsensitiveDict())
        self.add_attribute('raw', None)
        self.add_attribute('encoding', None)
        self.add_attribute('history', [])
        self.add_attribute('reason', None)
        self.add_attribute('elapsed', XDateTime().timedelta(0))
        self.add_attribute('request', None)
        self.add_attribute('auth', None)
        self.add_attribute('cookies', CookieUtils().cookiejar_from_dict({}))
        self.contentClass = Content(self.read_content)
        Resource('next_').variable('next_').add_get_and_set_to(self)

    def read_content(self):  # ./models/Response.py
        if self.status_code_() == 0 or self.raw_() is None:
            return None
        else:
            return b''.join(self.iter_content(Models().CONTENT_CHUNK_SIZE())) or b''

    def __enter__(self):  # ./models/Response.py
        return self

    def __exit__(self, *args):  # ./models/Response.py
        self.close()

    def __repr__(self):  # ./models/Response.py
        return '<Response [%s]>' % (self.status_code_())

    def __bool__(self):  # ./models/Response.py
        return self.ok_()

    def __nonzero__(self):  # ./models/Response.py
        return self.ok_()

    def __iter__(self):  # ./models/Response.py
        """Allows you to use a response as an iterator."""
        return self.iter_content(128)

    @property
    def ok(self):  # ./models/Response.py
        return self.ok_()

    def ok_(self):  # ./models/Response.py
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    @property
    def is_redirect(self):  # ./models/Response.py
        return self.is_redirect_()

    def is_redirect_(self):
        return 'location' in self.headers_() and self.status_code in Models().REDIRECT_STATI()

    @property
    def is_permanent_redirect(self):  # ./models/Response.py
        return self.is_permanent_redirect_()

    def is_permanent_redirect_(self):
        """True if this Response one of the permanent versions of redirect."""
        return ('location' in self.headers_() and self.status_code in (
            StatusCodes().get('moved_permanently'), StatusCodes().get('permanent_redirect')))

    @property
    def next(self):  # ./models/Response.py
        """Returns a PreparedRequest for the next request in a redirect chain, if there is one."""
        return self.next_()

    def iter_content(self, chunk_size=1, decode_unicode=False):  # ./models/Response.py
        return self.contentClass.iterate(chunk_size, decode_unicode, self.raw_(), self.encoding_())

    def iter_lines(self, chunk_size=-1, decode_unicode=False, delimiter=None):  # ./models/Response.py
        if chunk_size == -1:
            chunk_size = Models().ITER_CHUNK_SIZE()

        pending = None

        for chunk in self.iter_content(chunk_size=chunk_size, decode_unicode=decode_unicode):

            if pending is not None:
                chunk = pending + chunk

            if delimiter:
                lines = chunk.split(delimiter)
            else:
                lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending

    @property
    def content(self):  # ./models/Response.py
        """Content of the response, in bytes."""
        return self.contentClass.content()

    def content_(self, *args):  # ./models/Response.py
        return DomainUtils().get_or_set(self, 'content', *args)

    @property
    def text(self):  # ./models/Response.py
        return self.contentClass.text(self.encoding_())

    def json(self, **kwargs):  # ./models/Response.py
        return self.contentClass.json(self.encoding_(), **kwargs)

    @property
    def links(self):  # ./models/Response.py
        """Returns the parsed header links of the response, if any."""

        header = self.headers_().get('link')

        # l = MultiDict()
        result = {}

        if header:
            links = Header().parse_header_links(header)

            for link in links:
                key = link.get('rel') or link.get('url')
                result[key] = link

        return result

    def raise_for_status(self):  # ./models/Response.py
        """Raises :class:`HTTPError`, if one occurred."""

        http_error_msg = ''
        reason = Reason(self.reason_()).normalize()

        if 400 <= self.status_code < 500:
            http_error_msg = u'%s Client Error: %s for url: %s' % (self.status_code, reason, self.url_())

        elif 500 <= self.status_code < 600:
            http_error_msg = u'%s Server Error: %s for url: %s' % (self.status_code, reason, self.url_())

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    def close(self):  # ./models/Response.py
        self.contentClass.close(self.raw_())

        release_conn = getattr(self.raw_(), 'release_conn', None)
        if release_conn is not None:
            release_conn()

    def get_unicode(self):  # ./models/Response.py
        XWarnings().warn((
            'In requests 3.0, get_unicode will be removed. For '
            'more information, please see the discussion on issue #2266. (This'
            ' warning should only appear once.)'),
            DeprecationWarning)

        tried_encodings = []

        # Try charset from content-type
        encoding = self.get_encoding_from_headers(self.headers_())

        if encoding:
            try:
                return str(self.content_(), encoding)
            except UnicodeError:
                tried_encodings.append(encoding)

        # Fall back:
        try:
            return str(self.content_(), encoding, errors='replace')
        except TypeError:
            return self.content_()

class Reason:
    def __init__(self, value):
        self.value = value

    def raise_exception(self, e, request):
        if isinstance(self.value, XUrllib3().exceptions().ConnectTimeoutError):
            # TODO: Remove this in 3.0.0: see #2811
            if not isinstance(self.value, XUrllib3().exceptions().NewConnectionError):
                raise ConnectTimeout(e, request=request)

        if isinstance(self.value, XUrllib3().exceptions().ResponseError):
            raise RetryError(e, request=request)

        if isinstance(self.value, XUrllib3().exceptions().ProxyError):
            raise ProxyError(e, request=request)

        if isinstance(self.value, XUrllib3().exceptions().SSLError):
            # This branch is for urllib3 v1.22 and later.
            raise SSLError(e, request=request)

        raise ConnectionError(e, request=request)

    def normalize(self):  # ./models/Response.py
        if XBytes().is_instance(self.value):
            # We attempt to decode utf-8 first because some servers
            # choose to localize their reason strings. If the string
            # isn't utf-8, we fall back to iso-8859-1 for all other
            # encodings. (See PR #3538)
            try:
                reason = self.value.decode('utf-8')
            except UnicodeDecodeError:
                reason = self.value.decode('iso-8859-1')
        else:
            reason = self.value
        return reason


class ResponsePickle:  # ./models/Response/ResponsePickle.py
    def __init__(self, instance):
        self.instance = instance

    def state_(self, *args):
        it = self.instance
        if len(args) == 0:

            it.contentClass.consume_everything()
            it._content = it.contentClass.internal_content()
            attrs = [
                '_content', 'status_code', 'headers', 'url', 'history',
                'encoding', 'reason', 'cookies', 'elapsed', 'request'
            ]

            return {attr: getattr(it, attr, None) for attr in attrs}
        else:
            state = args[0]
            for name, value in state.items():
                setattr(it, name, value)

            it.contentClass = Content(it.read_content)
            it.contentClass.internal_content(it._content)

            # pickled objects do not have .raw
            it.contentClass.reset_content_consumed()
            setattr(it, 'raw', None)


# *************************** classes in Packages section *****************
class Packages:  # ./Packages/Packages.py
    def help(self): Help().display(self.__class__.__name__)

    def urllib3(self):
        return XUrllib3()

    def idna(self):
        return XIdna()

    def chardet(self):
        return XCharDet('../packages.py')


# *************************** classes in Sessions section *****************
class RequestSetting:  # ./Sessions/request_setting.py
    def __init__(self, request_setting):
        self.request_setting = request_setting

    def merge_session_setting(self, session_setting, dict_class=XOrderedDict):
        if session_setting is None:
            return self.request_setting

        if self.request_setting is None:
            return session_setting

        # Bypass if not a dictionary (e.g. verify)
        if not (isinstance(session_setting, XMapping) and
                isinstance(self.request_setting, XMapping)):
            return self.request_setting

        merged_setting = dict_class(CollectionsUtils().to_key_val_list(session_setting))
        merged_setting.update(CollectionsUtils().to_key_val_list(self.request_setting))

        # Remove keys that are set to None. Extract keys first to avoid altering
        # the dictionary during iteration.
        none_keys = [k for (k, v) in merged_setting.items() if v is None]
        for key in none_keys:
            del merged_setting[key]

        return merged_setting


class Sessions:  # ./Sessions/Sessions.py
    def help(self):
        Help().display(self.__class__.__name__)

    def preferred_clock(self):
        return XTime().clock_method()()

    def merge_hooks(self, request_hooks, session_hooks, dict_class=XOrderedDict):
        if session_hooks is None or session_hooks.get('response') == []:
            return request_hooks

        if request_hooks is None or request_hooks.get('response') == []:
            return session_hooks

        return RequestSetting(request_hooks).merge_session_setting(session_hooks, dict_class)

    def session(self):  # ./Sessions/Session.py
        return Session()


class SessionRedirect:  # ./Sessions/SessionRedirect.py
    def help(self):
        Help().display(self.__class__.__name__)

    def DEFAULT_PORTS(self):  # ./Sessions/SessionRedirect.py
        return {'http': 80, 'https': 443}

    def get_redirect_target(self, resp):
        """Receives a Response. Returns a redirect URI or ``None``"""
        # Due to the nature of how requests processes redirects this method will
        # be called at least once upon the original response and at least twice
        # on each subsequent redirect response (if any).
        # If a custom mixin is used to handle this logic, it may be advantageous
        # to cache the redirect location onto the response object as a private
        # attribute.
        if resp.is_redirect_():
            location = resp.headers_()['location']
            # Currently the underlying http module on py3 decode headers
            # in latin1, but empirical evidence suggests that latin1 is very
            # rarely used with non-ASCII characters in HTTP headers.
            # It is more likely to get UTF8 header rather than latin1.
            # This causes incorrect handling of UTF8 encoded location headers.
            # To solve this, we re-encode the location in latin1.
            location = location.encode('latin1')
            return XUtils().to_native_string(location, 'utf8')
        return None

    def should_strip_auth(self, old_url, new_url):  # ./Sessions/SessionRedirect.py
        """Decide whether Authorization header should be removed when redirecting"""
        old_parsed = Url(old_url).parse()
        new_parsed = Url(new_url).parse()
        if old_parsed.hostname != new_parsed.hostname:
            return True
        # Special case: allow http -> https redirect when using the standard
        # ports. This isn't specified by RFC 7235, but is kept to avoid
        # breaking backwards compatibility with older versions of requests
        # that allowed any redirects on the same host.
        if (old_parsed.scheme == 'http' and old_parsed.port in (80, None)
                and new_parsed.scheme == 'https' and new_parsed.port in (443, None)):
            return False

        # Handle default port usage corresponding to scheme.
        changed_port = old_parsed.port != new_parsed.port
        changed_scheme = old_parsed.scheme != new_parsed.scheme
        default_port = (self.DEFAULT_PORTS().get(old_parsed.scheme, None), None)
        if (not changed_scheme and old_parsed.port in default_port
                and new_parsed.port in default_port):
            return False

        # Standard case: root URI must match
        return changed_port or changed_scheme

    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None, yield_requests=False, **adapter_kwargs):
        # ./Sessions/SessionRedirect.py
        """Receives a Response. Returns a generator of Responses or Requests."""

        hist = []  # keep track of history

        url = self.get_redirect_target(resp)
        previous_fragment = req.url_obj().parse().fragment
        while url:
            prepared_request = req.copy()

            # Update history and keep track of redirects.
            # resp.history_( must ignore the original request in this loop
            hist.append(resp)
            resp.history_(hist[1:])

            try:
                resp.content_()  # Consume socket so it can be released
            except (ChunkedEncodingError, ContentDecodingError, RuntimeError):
                resp.raw_().read(decode_content=False)

            if len(resp.history_()) >= self.max_redirects_():
                raise TooManyRedirects('Exceeded {} redirects.'.format(self.max_redirects_()), response=resp)

            # Release the xconnection back into the xpool.
            resp.close()

            # Handle redirection without scheme (see: RFC 1808 Section 4)
            if url.startswith('//'):
                parsed_rurl = resp.url_obj().parse()
                url = ':'.join([XUtils().to_native_string(parsed_rurl.scheme), url])

            # Normalize url case and attach previous fragment if needed (RFC 7231 7.1.2)
            parsed = Url(url).parse()
            if parsed.fragment == '' and previous_fragment:
                parsed = parsed._replace(fragment=previous_fragment)
            elif parsed.fragment:
                previous_fragment = parsed.fragment
            url = parsed.geturl()

            # Facilitate relative 'location' headers, as allowed by RFC 7231.
            # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
            # Compliant with RFC3986, we percent encode the url.
            if not parsed.netloc:
                url = Url(resp.url_()).join(Uri(url).requote())
            else:
                url = Uri(url).requote()

            prepared_request.url_(XUtils().to_native_string(url))

            self.rebuild_method(prepared_request, resp)

            # https://github.com/psf/requests/issues/1084
            if resp.status_code not in (
                    StatusCodes().get('temporary_redirect'), StatusCodes().get('permanent_redirect')):
                # https://github.com/psf/requests/issues/3490
                purged_headers = ('Content-Length', 'Content-Type', 'Transfer-Encoding')
                for header in purged_headers:
                    prepared_request.headers_().pop(header, None)
                prepared_request.body_(None)

            headers = prepared_request.headers_()
            headers.pop('Cookie', None)

            # Extract any cookies sent on the response to the cookiejar
            # in the new request. Because we've mutated our copied prepared
            # request, use the old one that we haven't yet touched.
            CookieUtils().to_jar(prepared_request.cookies_(), req, resp.raw_())
            CookieUtils().merge_cookies(prepared_request.cookies_(), self.cookies_())
            prepared_request.prepare_cookies(prepared_request.cookies_())

            # Rebuild auth and proxy information.
            proxies = self.rebuild_proxies(prepared_request, proxies)
            self.rebuild_auth(prepared_request, resp)

            # A failed tell() sets `_body_position` to `object()`. This non-None
            # value ensures `rewindable` will be True, allowing us to raise an
            # UnrewindableBodyError, instead of hanging the xconnection.
            rewindable = (
                    prepared_request._body_position is not None and
                    ('Content-Length' in headers or 'Transfer-Encoding' in headers)
            )

            # Attempt to rewind consumed file-like object.
            if rewindable:
                FileUtils().rewind_body(prepared_request)

            # Override the original request.
            req = prepared_request

            if yield_requests:
                yield req
            else:

                resp = self.send(
                    req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    allow_redirects=False,
                    **adapter_kwargs
                )

                CookieUtils().to_jar(self.cookies_(), prepared_request, resp.raw_())

                # extract redirect url, if any, for the next loop
                url = self.get_redirect_target(resp)
                yield resp

    def rebuild_auth(self, prepared_request, response):  # ./Sessions/SessionRedirect.py
        """When being redirected we may want to strip authentication from the
        request to avoid leaking credentials. This method intelligently removes
        and reapplies authentication where possible to avoid credential loss.
        """
        headers = prepared_request.headers_()
        url = prepared_request.url_obj()

        if 'Authorization' in headers and self.should_strip_auth(response.request_().url_(), url.value_()):
            # If we get redirected to a new host, we should strip out any
            # authentication headers.
            del headers['Authorization']

        # .netrc might have more auth for us on our new host.
        new_auth = url.get_netrc_auth() if self.trust_env_() else None
        if new_auth is not None:
            prepared_request.prepare_auth(new_auth)

    def rebuild_proxies(self, prepared_request, proxies):  # ./Sessions/SessionRedirect.py
        """This method re-evaluates the proxy configuration by considering the
        environment variables. If we are redirected to a URL covered by
        NO_PROXY, we strip the proxy configuration. Otherwise, we set missing
        proxy keys for this URL (in case they were stripped by a previous
        redirect).

        This method also replaces the Proxy-Authorization header where
        necessary.

        :rtype: dict
        """
        proxies = proxies if proxies is not None else {}
        headers = prepared_request.headers_()
        url = prepared_request.url_()
        scheme = Url(url).parse().scheme
        new_proxies = proxies.copy()
        no_proxy = proxies.get('no_proxy')

        bypass_proxy = Proxies().should_bypass_proxies(url, no_proxy=no_proxy)
        if self.trust_env_() and not bypass_proxy:
            environ_proxies = Proxies().get_environ_proxies(url, no_proxy=no_proxy)

            proxy = environ_proxies.get(scheme, environ_proxies.get('all'))

            if proxy:
                new_proxies.setdefault(scheme, proxy)

        if 'Proxy-Authorization' in headers:
            del headers_()['Proxy-Authorization']

        try:
            username, password = Url(new_proxies[scheme]).get_auth()
        except KeyError:
            username, password = None, None

        if username and password:
            headers_()['Proxy-Authorization'] = Auth().basic_auth_str(username, password)

        return new_proxies

    def rebuild_method(self, prepared_request, response):  # ./Sessions/SessionRedirect.py
        """When being redirected we may want to change the method of the request
        based on certain specs or browser behavior.
        """
        method = prepared_request.method_obj().rebuild(response.status_code_())
        prepared_request.method_(method)

    def cookies_(self, *args):  # ./models/Response.py
        return DomainUtils().get_or_set(self, 'cookies', *args)

    def trust_env_(self, *args):  # ./Sessions/Session.py
        return DomainUtils().get_or_set(self, 'trust_env', *args)

    def max_redirects_(self, *args):  # ./Sessions/Session.py
        return DomainUtils().get_or_set(self, 'max_redirects', *args)


class SessionPickle:
    def __init__(self, instance):
        self.instance = instance

    def state_(self, *args):
        it = self.instance
        if len(args) == 0:
            attrs = [
                'headers', 'cookies', 'auth', 'proxies', 'hooks', 'params', 'verify',
                'cert', 'adapters', 'stream', 'trust_env',
                'max_redirects',
            ]
            state = {attr: getattr(it, attr, None) for attr in attrs}
            return state
        else:
            for attr, value in args[0].items():
                setattr(it, attr, value)


class SessionSendInputs(Attributes):
    def __init__(self):
        super(SessionSendInputs, self).__init__()
        self.add_attribute('timeout', None)
        self.add_attribute('allow_redirects', True)

    def merge_settings(self, settings):
        send_kwargs = {
            'timeout': self.timeout,
            'allow_redirects': self.allow_redirects,
        }
        send_kwargs.update(settings)
        return send_kwargs


class SessionEnvironmentInputs(Attributes):  # ./sessions/session_environment_inputs.py
    def __init__(self):
        super(SessionEnvironmentInputs, self).__init__()
        self.add_attribute('verify', None)
        self.add_attribute('proxies', None)
        self.add_attribute('stream', None)
        self.add_attribute('cert', None)

    def merge_settings(self, url, session):  # ./sessions/session_environment_inputs.py
        self.proxies = self.proxies or {}
        if session.trust_env_():
            # Set environment's proxies.
            no_proxy = self.proxies.get('no_proxy') if self.proxies is not None else None
            env_proxies = Proxies().get_environ_proxies(url, no_proxy=no_proxy)
            for (k, v) in env_proxies.items():
                self.proxies.setdefault(k, v)

            # Look for requests environment configuration and be compatible
            # with cURL.
            if self.verify is True or self.verify is None:
                self.verify = (XOs().environ().get('REQUESTS_CA_BUNDLE') or
                               XOs().environ().get('CURL_CA_BUNDLE'))

        # Merge all the kwargs.
        proxies = RequestSetting(self.proxies).merge_session_setting(session.proxies_())
        stream = RequestSetting(self.stream).merge_session_setting(session.stream_())
        verify = RequestSetting(self.verify).merge_session_setting(session.verify_())
        cert = RequestSetting(self.cert_()).merge_session_setting(session.cert_())

        return {'verify': verify, 'proxies': proxies, 'stream': stream,
                'cert': cert}


class Session(SessionRedirect, Pickler, Attributes):  # ./Sessions/Session.py
    def help(self):
        Help().display(self.__class__.__name__)

    def __init__(self):  # ./Sessions/Session.py
        super(Session, self).__init__()
        self.add_attribute('headers', Headers().default_headers())
        self.add_attribute('auth', None)
        self.add_attribute('proxies', {})
        self.add_attribute('hooks', Hooks().default_hooks())
        self.add_attribute('params', {})
        self.add_attribute('stream', False)
        self.add_attribute('verify', True)
        self.add_attribute('cert', None)
        self.add_attribute('max_redirects', Models().DEFAULT_REDIRECT_LIMIT())
        self.add_attribute('trust_env', True)
        self.add_attribute('cookies', CookieUtils().cookiejar_from_dict({}))
        self.add_attribute('adapters', XOrderedDict())
        self.mount('https://', HTTPconnections())
        self.mount('http://', HTTPconnections())

    def __enter__(self):  # ./Sessions/Session.py
        return self

    def __exit__(self, *args):
        self.close()

    def prepare_ticket(self, request):  # ./sessions/session.py
        cookies = request.cookies_() or {}

        # Bootstrap CookieJar.
        if not isinstance(cookies, XCookieJar):
            cookies = CookieUtils().cookiejar_from_dict(cookies)

        # Merge with session cookies
        merged_cookies = CookieUtils().merge_cookies(
            CookieUtils().merge_cookies(CookieJar(), self.cookies_()), cookies)

        # Set environment's basic authentication if not explicitly set.
        auth = request.auth_()
        if self.trust_env_() and not auth and not self.auth_():
            auth = request.url_obj().get_netrc_auth()

        return Ticket() \
            .method_(request.method_().upper()) \
            .url_(request.url_()) \
            .files_(request.files_()) \
            .data_(request.data_()) \
            .json_(request.json_()) \
            .headers_(RequestSetting(request.headers_())
                      .merge_session_setting(self.headers_(), dict_class=CaseInsensitiveDict)) \
            .params_(RequestSetting(request.params_()).merge_session_setting(self.params_())) \
            .auth_(RequestSetting(auth).merge_session_setting(self.auth_())) \
            .cookies_(merged_cookies) \
            .hooks_(Sessions().merge_hooks(request.hooks_(), self.hooks_())).prepare()

    def request(self, method, url, **kwargs):  # ./sessions/session.py
        req = Request().url_(url).method_(method).pick_out_inputs(kwargs)
        ticket = self.prepare_ticket(req)
        settings = SessionEnvironmentInputs().pick_out_inputs(kwargs).merge_settings(ticket.url_(), self)
        send_kwargs = SessionSendInputs().pick_out_inputs(kwargs).merge_settings(settings)
        resp = self.send(ticket, **send_kwargs)
        return resp

    def get(self, url, **kwargs):  # ./Sessions/Session.py
        kwargs.setdefault('allow_redirects', True)
        return self.request('GET', url, **kwargs)

    def options(self, url, **kwargs):
        kwargs.setdefault('allow_redirects', True)
        return self.request('OPTIONS', url, **kwargs)

    def head(self, url, **kwargs):  # ./Sessions/Session.py
        kwargs.setdefault('allow_redirects', False)
        return self.request('HEAD', url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):  # ./Sessions/Session.py
        return self.request('POST', url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):  # ./Sessions/Session.py
        return self.request('PUT', url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):  # ./Sessions/Session.py
        return self.request('PATCH', url, data=data, **kwargs)

    def delete(self, url, **kwargs):  # ./Sessions/Session.py
        return self.request('DELETE', url, **kwargs)

    def send(self, ticket, **kwargs):  # ./Sessions/Session.py
        kwargs.setdefault('stream', self.stream_())
        kwargs.setdefault('verify', self.verify_())
        kwargs.setdefault('cert', self.cert_())
        if 'proxies' not in kwargs:
            kwargs['proxies'] = self.proxies_obj().resolve_proxies(
                ticket, self.trust_env_()
            )

        # It's possible that users might accidentally send a Request object.
        # Guard against that specific failure case.
        if isinstance(ticket, Request):
            raise ValueError('You can only send Tickets, not Requests.')

        # Set up variables needed for resolve_redirects and dispatching of hooks
        allow_redirects = kwargs.pop('allow_redirects', True)
        stream = kwargs.get('stream')
        hooks = ticket.hooks_()

        # Get the appropriate adapter to use
        adapter = self.get_adapter(url=ticket.url_())

        # Start time (approximately) of the request
        start = Sessions().preferred_clock()

        # Send the request
        r = adapter.send(ticket, **kwargs)

        # Total elapsed time of the request (approximately)
        elapsed = Sessions().preferred_clock() - start
        r.elapsed_(XDateTime().timedelta(seconds=elapsed))

        # Response manipulation hooks
        r = Hooks().dispatch_hook('response', hooks, r, **kwargs)

        # Persist cookies
        if r.history_():

            # If the hooks create history then we want those cookies too
            for resp in r.history_():
                CookieUtils().to_jar(self.cookies_(), resp.request_(), resp.raw_())

        CookieUtils().to_jar(self.cookies_(), ticket, r.raw_())

        # Resolve redirects if allowed.
        if allow_redirects:
            # Redirect resolving generator.
            gen = self.resolve_redirects(r, ticket, **kwargs)
            history = [resp for resp in gen]
        else:
            history = []

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history_(history)

        # If redirects aren't being followed, store the response on the Request for Response.next_().
        if not allow_redirects:
            try:
                r.next_(next(self.resolve_redirects(r, ticket, yield_requests=True, **kwargs)))
            except StopIteration:
                pass

        if not stream:
            r.content_()

        return r

    def get_adapter(self, url):  # ./Sessions/Session.py
        for (prefix, adapter) in self.adapters_().items():

            if url.lower().startswith(prefix.lower()):
                return adapter

        # Nothing matches :-/
        raise InvalidSchema("No connection adapters were found for {!r}".format(url))

    def close(self):
        for v in self.adapters_().values():
            v.close()

    def mount(self, prefix, adapter):  # ./Sessions/Session.py
        self.adapters_()[prefix] = adapter
        keys_to_move = [k for k in self.adapters_() if len(k) < len(prefix)]

        for key in keys_to_move:
            self.adapters_()[key] = self.adapters_().pop(key)


# *************************** classes in Utils section *****************
class Proxies:  # ./Utils/proxies.py
    def __init__(self, input=None):
        Resource('value_').initial_value(input).add_get_and_set_to(self)

    def help(self):
        Help().display(self.__class__.__name__)

    def proxy_bypass(self, host):  # noqa  # ./Utils/proxies.py
        if XSys().platform() == 'win32':
            return self._proxy_bypass_win32(host)
        else:
            return XUrl().request().proxy_bypass(host)

    if XSys().platform() == 'win32':
        # provide a proxy_bypass version on Windows without DNS lookups

        def proxy_bypass_registry(self, host):  # ./Utils/utils.py
            winreg = XWinReg()

            try:
                internetSettings = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                                  r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
                # ProxyEnable could be REG_SZ or REG_DWORD, normalizing it
                proxyEnable = int(winreg.QueryValueEx(internetSettings,
                                                      'ProxyEnable')[0])
                # ProxyOverride is almost always a string
                proxyOverride = winreg.QueryValueEx(internetSettings,
                                                    'ProxyOverride')[0]
            except OSError:
                return False
            if not proxyEnable or not proxyOverride:
                return False

            # make a check value list from the registry entry: replace the
            # '<local>' string by the localhost entry and the corresponding
            # canonical entry.
            proxyOverride = proxyOverride.split(';')
            # now check if we match one of the registry values.
            for test in proxyOverride:
                if test == '<local>':
                    if '.' not in host:
                        return True
                test = test.replace(".", r"\.")  # mask dots
                test = test.replace("*", r".*")  # change glob sequence
                test = test.replace("?", r".")  # change glob char
                if XRe().match(test, host, XRe().I()):
                    return True
            return False

        def _proxy_bypass_win32(self, host):  # noqa  # ./Utils/utils.py
            if XCompat().getproxies_environment():
                return XCompat().proxy_bypass_environment(host)
            else:
                return XCompat().proxy_bypass_registry(host)

    def should_bypass_proxies(self, url, no_proxy):  # ./Utils/proxies.py
        def get_proxy(k):
            return XOs().environ().get(k) or XOs().environ().get(k.upper())

        # First check whether no_proxy is defined. If it is, check that the URL
        # we're getting isn't in the no_proxy list.
        no_proxy_arg = no_proxy
        if no_proxy is None:
            no_proxy = get_proxy('no_proxy')
        parsed = Url(url).parse()

        if parsed.hostname is None:
            # URLs don't always have hostnames, e.g. file:/// urls.
            return True

        if no_proxy:
            # We need to check whether we match here. We need to see if we match
            # the end of the hostname, both with and without the port.
            no_proxy = (
                host for host in no_proxy.replace(' ', '').split(',') if host
            )

            if IpUtils().is_ipv4_address(parsed.hostname):
                for proxy_ip in no_proxy:
                    if self.is_valid_cidr(proxy_ip):
                        if self.address_in_network(parsed.hostname, proxy_ip):
                            return True
                    elif parsed.hostname == proxy_ip:
                        # If no_proxy ip was defined in plain IP notation instead of cidr notation &
                        # matches the IP of the index
                        return True
            else:
                host_with_port = parsed.hostname
                if parsed.port:
                    host_with_port += ':{}'.format(parsed.port)

                for host in no_proxy:
                    if parsed.hostname.endswith(host) or host_with_port.endswith(host):
                        # The URL does match something in no_proxy, so we don't want
                        # to apply the proxies on this URL.
                        return True

        with Utils().set_environ('no_proxy', no_proxy_arg):
            # parsed.hostname can be `None` in cases such as a file URI.
            try:
                bypass = self.proxy_bypass(parsed.hostname)
            except (TypeError, XSocket().gaierror()):
                bypass = False

        if bypass:
            return True

        return False

    def address_in_network(self, ip, net):  # ./Utils/proxies.py
        ipaddr = XStruct().unpack('=L', XSocket().inet_aton(ip))[0]
        netaddr, bits = net.split('/')
        netmask = XStruct().unpack('=L', XSocket().inet_aton(self.dotted_netmask(int(bits))))[0]
        network = XStruct().unpack('=L', XSocket().inet_aton(netaddr))[0] & netmask
        return (ipaddr & netmask) == (network & netmask)

    def dotted_netmask(self, mask):  # ./Utils/proxies.py
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return XSocket().inet_ntoa(XStruct().pack('>I', bits))

    def is_valid_cidr(self, string_network):  # ./Utils/proxies.py
        if string_network.count('/') == 1:
            try:
                mask = int(string_network.split('/')[1])
            except ValueError:
                return False

            if mask < 1 or mask > 32:
                return False

            try:
                XSocket().inet_aton(string_network.split('/')[0])
            except XSocket().error():
                return False
        else:
            return False
        return True

    def get_environ_proxies(self, url, no_proxy=None):  # ./Utils/proxies.py
        if self.should_bypass_proxies(url, no_proxy=no_proxy):
            return {}
        else:
            return XUrl().request().getproxies()

    def select_proxy(self, url):  # ./Utils/proxies.py
        proxies = self.value_() or {}
        urlparts = Url(url).parse()
        if urlparts.hostname is None:
            return proxies.get(urlparts.scheme, proxies.get('all'))

        proxy_keys = [
            urlparts.scheme + '://' + urlparts.hostname,
            urlparts.scheme,
            'all://' + urlparts.hostname,
            'all',
        ]
        proxy = None
        for proxy_key in proxy_keys:
            if proxy_key in proxies:
                proxy = proxies[proxy_key]
                break

        return proxy

    def resolve_proxies(self, request, trust_env=True):  # ./Utils/proxies.py
        proxies = self.value_()
        proxies = proxies if proxies is not None else {}
        url = request.url_()
        scheme = Url(url).parse().scheme
        no_proxy = proxies.get('no_proxy')
        new_proxies = proxies.copy()

        bypass_proxy = self.should_bypass_proxies(url, no_proxy=no_proxy)
        if trust_env and not bypass_proxy:
            environ_proxies = self.get_environ_proxies(url, no_proxy=no_proxy)

            proxy = environ_proxies.get(scheme, environ_proxies.get('all'))

            if proxy:
                new_proxies.setdefault(scheme, proxy)
        return new_proxies


class CollectionsUtils:  # ./Utils/collections_utils.py
    def help(self):
        Help().display(self.__class__.__name__)

    def to_key_val_list(self, value):  # ./Utils/collections_utils.py
        if value is None:
            return None
        if isinstance(value, (XStr().clazz(), XBytes().clazz(), bool, int)):
            raise ValueError('cannot encode objects that are not 2-tuples')

        if isinstance(value, XMapping):
            value = value.items()

        return list(value)


class WSGIutils:  # ./Utils/wsgi_utils.py
    def help(self):
        Help().display(self.__class__.__name__)

    # From mitsuhiko/werkzeug (used with permission).
    def parse_dict_header(self, value):  # ./Utils/wsgi_utils.py
        result = {}
        for item in _parse_list_header(value):
            if '=' not in item:
                result[item] = None
                continue
            name, value = item.split('=', 1)
            if value[:1] == value[-1:] == '"':
                value = WSGIutils().unquote_header_value(value[1:-1])
            result[name] = value
        return result

    # From mitsuhiko/werkzeug (used with permission).
    def unquote_header_value(self, value, is_filename=False):  # ./Utils/wsgi_utils.py
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


class FileUtils:  # ./Utils/file_utils.py
    def help(self):
        Help().display(self.__class__.__name__)

    def guess_filename(self, obj):  # ./Utils/file_utils.py
        """Tries to guess the filename of the given object."""
        name = getattr(obj, 'name', None)
        if (name and XBaseString().is_instance(name) and name[0] != '<' and
                name[-1] != '>'):
            return XOs().path().basename(name)

    @contextlib.contextmanager
    def atomic_open(self, filename):  # ./Utils/file_utils.py
        """Write a file to the disk in an atomic fashion"""
        replacer = XOs().rename if XSys().version_info()[0] == 2 else XOs().replace
        tmp_descriptor, tmp_name = XTempFile().mkstemp(dir=XOs().path().dirname(filename))
        try:
            with XOs().fdopen(tmp_descriptor, 'wb') as tmp_handler:
                yield tmp_handler
            replacer(tmp_name, filename)
        except BaseException:
            XOs().remove(tmp_name)
            raise

    def rewind_body(self, prepared_request):  # ./Utils/file_utils.py
        body_seek = getattr(prepared_request.body_(), 'seek', None)
        if body_seek is not None and isinstance(prepared_request._body_position, XCompat().integer_types()):
            try:
                body_seek(prepared_request._body_position)
            except (IOError, OSError):
                raise UnrewindableBodyError("An error occurred when rewinding request "
                                            "body for redirect.")
        else:
            raise UnrewindableBodyError("Unable to rewind request body for redirect.")


class Uri:  # ./Utils/uri.py
    def help(self):
        Help().display(self.__class__.__name__)

    _UNRESERVED_SET = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789-._~")

    def __init__(self, uri):
        self.uri = uri

    # The unreserved URI characters (RFC 3986)
    def UNRESERVED_SET(self):  # ./Utils/uri.py
        return self._UNRESERVED_SET

    def unquote_unreserved(self):  # ./Utils/uri.py
        parts = self.uri.split('%')
        for i in range(1, len(parts)):
            h = parts[i][0:2]
            if len(h) == 2 and h.isalnum():
                try:
                    c = chr(int(h, 16))
                except ValueError:
                    raise InvalidURL("Invalid percent-escape sequence: '%s'" % h)

                if c in self.UNRESERVED_SET():
                    parts[i] = c + parts[i][2:]
                else:
                    parts[i] = '%' + parts[i]
            else:
                parts[i] = '%' + parts[i]
        return ''.join(parts)

    def requote(self):  # ./Utils/uri.py
        safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
        safe_without_percent = "!#$&'()*+,/:;=?@[]~"
        try:
            # Unquote only the unreserved characters
            # Then quote only illegal characters (do not quote reserved,
            # unreserved, or '%')
            return XUrl().quote(Uri(self.uri).unquote_unreserved(), safe=safe_with_percent)
        except InvalidURL:
            # We couldn't unquote the given URI, so let's try quoting it, but
            # there may be unquoted '%'s in the URI. We need to make sure they're
            # properly quoted so they do not cause issues elsewhere.
            return XUrl().quote(self.uri, safe=safe_without_percent)


class Url:  # ./Utils/url.py
    def __init__(self, input):
        Resource('value_').initial_value(input).add_get_and_set_to(self)

    def help(self):
        Help().display(self.__class__.__name__)

    _NETRC_FILES = ('.netrc', '_netrc')

    def get_netrc_auth(self, raise_errors=False):  # ./Utils/url.py
        """Returns the Requests tuple auth for a given url from netrc."""

        netrc_file = XOs().environ().get('NETRC')
        if netrc_file is not None:
            netrc_locations = (netrc_file,)
        else:
            netrc_locations = ('~/{}'.format(f) for f in self._NETRC_FILES)

        try:
            from netrc import netrc, NetrcParseError

            netrc_path = None

            for f in netrc_locations:
                try:
                    loc = XOs().path().expanduser(f)
                except KeyError:
                    # os.path.expanduser can fail when $HOME is undefined and
                    # getpwuid fails. See https://bugs.python.org/issue20164 &
                    # https://github.com/psf/requests/issues/1846
                    return

                if XOs().path().exists(loc):
                    netrc_path = loc
                    break

            # Abort early if there isn't one.
            if netrc_path is None:
                return

            ri = self.parse()

            # Strip port numbers from netloc. This weird `if...encode`` dance is
            # used for Python 3.2, which doesn't support unicode literals.
            splitstr = b':'
            if XStr().is_instance(self.value_()):
                splitstr = splitstr.decode('ascii')
            host = ri.netloc.split(splitstr)[0]

            try:
                _netrc = netrc(netrc_path).authenticators(host)
                if _netrc:
                    # Return with login / password
                    login_i = (0 if _netrc[0] else 1)
                    return _netrc[login_i], _netrc[2]
            except (NetrcParseError, IOError):
                # If there was a parsing error or a permissions issue reading the file,
                # we'll just skip netrc auth unless explicitly asked to raise errors.
                if raise_errors:
                    raise

        # App Engine hackiness.
        except (ImportError, AttributeError):
            pass

    def prepend_scheme_if_needed(self, new_scheme):  # ./Utils/url.py
        scheme, netloc, path, params, query, fragment = self.parse(new_scheme)

        # urlparse is a finicky beast, and sometimes decides that there isn't a
        # netloc present. Assume that it's being over-cautious, and switch netloc
        # and path if urlparse decided there was no netloc.
        if not netloc:
            netloc, path = path, netloc

        return XUrl().unparse((scheme, netloc, path, params, query, fragment))

    def get_auth(self):  # ./Utils/url.py
        parsed = self.parse()

        try:
            auth = (XUrl().unquote(parsed.username), XUrl().unquote(parsed.password))
        except (AttributeError, TypeError):
            auth = ('', '')

        return auth

    def defragauth(self):  # ./Utils/url.py
        scheme, netloc, path, params, query, fragment = self.parse()
        # see func:`prepend_scheme_if_needed`
        if not netloc:
            netloc, path = path, netloc

        netloc = netloc.rsplit('@', 1)[-1]

        return XUrl().unparse((scheme, netloc, path, params, query, ''))

    def prepare(self, params):  # ./Utils/url.py
        url = self.value_()
        if XBytes().is_instance(url):
            url = url.decode('utf8')
        else:
            url = XStr().new(url)

        # Remove leading whitespaces from url
        url = url.lstrip()

        # Don't do any URL preparation for non-HTTP schemes like `mailto`,
        # `data` etc to work around exceptions from `url_parse`, which
        # handles RFC 3986 only.
        if ':' in url and not url.lower().startswith('http'):
            self.value_(url)
            return self

        # Support for unicode domain names and paths.
        try:
            scheme, auth, host, port, path, query, fragment = XUrllib3().util().parse_url(url)
        except XUrllib3().exceptions().LocationParseError as e:
            raise InvalidURL(*e.args)

        if not scheme:
            error = "Invalid URL {0!r}: No schema supplied. Perhaps you meant http://{0}?"
            error = error.format(XUtils().to_native_string(url, 'utf8'))

            raise MissingSchema(error)

        if not host:
            raise InvalidURL("Invalid URL %r: No host supplied" % url)

        # In general, we want to try IDNA encoding the hostname if the string contains
        # non-ASCII characters. This allows users to automatically get the correct IDNA
        # behaviour. For strings containing only ASCII characters, we need to also verify
        # it doesn't start with a wildcard (*), before allowing the unencoded hostname.
        if not XUtils().unicode_is_ascii(host):
            try:
                host = self._get_idna_encoded_host(host)
            except UnicodeError:
                raise InvalidURL('URL has an invalid label.')
        elif host.startswith(u'*'):
            raise InvalidURL('URL has an invalid label.')

        # Carefully reconstruct the network location
        netloc = auth or ''
        if netloc:
            netloc += '@'
        netloc += host
        if port:
            netloc += ':' + XStr().new(port)

        # Bare domains aren't valid URLs.
        if not path:
            path = '/'

        if isinstance(params, (XStr().clazz(), XBytes().clazz())):
            params = XUtils().to_native_string(params)

        enc_params = Encoding().params(params)
        if enc_params:
            if query:
                query = '%s&%s' % (query, enc_params)
            else:
                query = enc_params

        url = Uri(XUrl().unparse([scheme, netloc, path, None, query, fragment])).requote()
        self.value_(url)
        return self

    def parse(self, *args):
        return XUrl().parse(self.value_(), *args)

    def split(self, *args):
        return XUrl().split(self.value_(), *args)

    def join(self, *args):
        return XUrl().join(self.value_(), *args)


class IpUtils:  # ./Utils/ip_utils.py
    def is_ipv4_address(self, string_ip):  # ./Utils/ip_utils.py
        try:
            XSocket().inet_aton(string_ip)
        except XSocket().error():
            return False
        return True


class Utils:  # ./Utils/utils.py
    def help(self):
        Help().display(self.__class__.__name__)

    _DEFAULT_CA_BUNDLE_PATH = Certs().where()

    _DEFAULT_PORTS = {'http': 80, 'https': 443}

    # Null bytes; no need to recreate these on each call to guess_json_utf
    _null = '\x00'.encode('ascii')  # encoding to ASCII for Python 3
    _null2 = _null * 2
    _null3 = _null * 3

    def DEFAULT_CA_BUNDLE_PATH(self):  # ./Utils/utils.py
        return self._DEFAULT_CA_BUNDLE_PATH

    def super_len(self, o):  # ./Utils/utils.py
        total_length = None
        current_position = 0

        if hasattr(o, '__len__'):
            total_length = len(o)

        elif hasattr(o, 'len'):
            total_length = o.len

        elif hasattr(o, 'fileno'):
            try:
                fileno = o.fileno()
            except (XIo().UnsupportedOperation(), AttributeError):
                # AttributeError is a surprising exception, seeing as how we've just checked
                # that `hasattr(o, 'fileno')`.  It happens for objects obtained via
                # `Tarfile.extractfile()`, per issue 5229.
                pass
            else:
                total_length = XOs().fstat(fileno).st_size

                # Having used fstat to determine the file length, we need to
                # confirm that this file was opened up in binary mode.
                if 'b' not in o.mode:
                    XWarnings().warn((
                        "Requests has determined the content-length for this "
                        "request using the binary size of the file: however, the "
                        "file has been opened in text mode (i.e. without the 'b' "
                        "flag in the mode). This may lead to an incorrect "
                        "content-length. In Requests 3.0, support will be removed "
                        "for files in text mode."),
                        FileModeWarning
                    )

        if hasattr(o, 'tell'):
            try:
                current_position = o.tell()
            except (OSError, IOError):
                # This can happen in some weird situations, such as when the file
                # is actually a special file descriptor like stdin. In this
                # instance, we don't know what the length is, so set it to zero and
                # let requests chunk it instead.
                if total_length is not None:
                    current_position = total_length
            else:
                if hasattr(o, 'seek') and total_length is None:
                    # StringIO and BytesIO have seek but no useable fileno
                    try:
                        # seek to end of file
                        o.seek(0, 2)
                        total_length = o.tell()

                        # seek back to current position to support
                        # partially read file-like objects
                        o.seek(current_position or 0)
                    except (OSError, IOError):
                        total_length = 0

        if total_length is None:
            total_length = 0

        return max(0, total_length - current_position)

    def extract_zipped_paths(self, path):  # ./Utils/utils.py
        if XOs().path().exists(path):
            # this is already a valid path, no need to do anything further
            return path

        # find the first valid part of the provided path and treat that as a zip archive
        # assume the rest of the path is the name of a member in the archive
        archive, member = XOs().path().split(path)
        while archive and not XOs().path().exists(archive):
            archive, prefix = XOs().path().split(archive)
            if not prefix:
                # If we don't check for an empty prefix after the split
                # (in other words, archive remains unchanged after the split),
                # we _can_ end up in an infinite loop on a rare corner case affecting a small number of users
                break
            member = '/'.join([prefix, member])

        if not XZipfile().is_zipfile(archive):
            return path

        zip_file = XZipfile().ZipFile(archive)
        if member not in zip_file.namelist():
            return path

        # we have a valid zip archive and a valid member of that archive
        tmp = XTempFile().gettempdir()
        extracted_path = XOs().path().join(tmp, member.split('/')[-1])
        if not XOs().path().exists(extracted_path):
            # use read + write to avoid creating nested folders, we only want the file, avoids mkdir racing condition
            with FileUtils().atomic_open(extracted_path) as file_handler:
                file_handler.write(zip_file.read(member))
        return extracted_path

    def stream_decode_response_unicode(self, iterator, encoding):  # ./Utils/utils.py
        if encoding is None:
            for item in iterator:
                yield item
            return

        decoder = XCodecs().getincrementaldecoder(encoding)(errors='replace')
        for chunk in iterator:
            rv = decoder.decode(chunk)
            if rv:
                yield rv
        rv = decoder.decode(b'', final=True)
        if rv:
            yield rv

    def iter_slices(self, string, slice_length):  # ./Utils/utils.py
        pos = 0
        if slice_length is None or slice_length <= 0:
            slice_length = len(string)
        while pos < len(string):
            yield string[pos:pos + slice_length]
            pos += slice_length

    @contextlib.contextmanager
    def set_environ(self, env_name, value):  # ./Utils/utils.py
        value_changed = value is not None
        if value_changed:
            old_value = XOs().environ().get(env_name)
            XOs().environ()[env_name] = value
        try:
            yield
        finally:
            if value_changed:
                if old_value is None:
                    del XOs().environ()[env_name]
                else:
                    XOs().environ()[env_name] = old_value

    def guess_json_utf(self, data):  # ./Utils/utils.py
        sample = data[:4]
        if sample in (XCodecs().BOM_UTF32_LE(), XCodecs().BOM_UTF32_BE()):
            return 'utf-32'  # BOM included
        if sample[:3] == XCodecs().BOM_UTF8():
            return 'utf-8-sig'  # BOM included, MS style (discouraged)
        if sample[:2] in (XCodecs().BOM_UTF16_LE(), XCodecs().BOM_UTF16_BE()):
            return 'utf-16'  # BOM included
        nullcount = sample.count(self._null)
        if nullcount == 0:
            return 'utf-8'
        if nullcount == 2:
            if sample[::2] == self._null2:  # 1st and 3rd are null
                return 'utf-16-be'
            if sample[1::2] == self._null2:  # 2nd and 4th are null
                return 'utf-16-le'
            # Did not detect 2 valid UTF-16 ascii-range characters
        if nullcount == 3:
            if sample[:3] == self._null3:
                return 'utf-32-be'
            if sample[1:] == self._null3:
                return 'utf-32-le'
            # Did not detect a valid UTF-32 ascii-range character
        return None


# *************************** Main section for calling domain.py directly *****************
def main():
    """Pretty-print the bug information as JSON."""
    print(XJson().dumps(Info().info(), sort_keys=True, indent=2))
    print(Certs().where())


if __name__ == '__main__':
    main()


class DomainUtils:
    def get_or_set(self, instance, variable, *args):
        if len(args) != 0:
            setattr(instance, variable, args[0])
            return instance
        return getattr(instance, variable)

    def get_or_set_class(self, instance, clazz, variable, *args):
        if len(args) != 0:
            if type(args[0]) == clazz:
                setattr(instance, variable, args[0])
            else:
                setattr(instance, variable, clazz(args[0]))
            return instance
        return getattr(instance, variable)