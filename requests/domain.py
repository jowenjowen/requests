# -*- coding: utf-8 -*-

# domain.py contains the code related to the domain
# (use an ide showing class structures for navigation)

from requests.x import XPlatform, XJson, XUrllib3, XSys, XCharSetNormalizer, XCharDet, \
    XOpenSSL, XIdna, XCryptography, XSsl, XPyOpenSsl, XMutableMapping, XOrderedDict, XMapping

from . import __version__ as requests_version

#         Help
#             class Help
#         Api
#             class Api
#         Structures
#             class Structures


class CaseInsensitiveDict(XMutableMapping):   # ./Structures/CaseInsensitiveDict.py
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

