# x.py contains all the external libraries used wrapped in objects
import io
import json
import platform
import ssl
import sys

import idna
import urllib3
from collections import OrderedDict as XOrderedDict
from .compat import CompatMapping as XMapping
from .compat import CompatMutableMapping as XMutableMapping
from .compat import conpat_basestring
import warnings
from base64 import b64encode

# imports for XWarnings, XBase64, XCompat, XThreading, XHashLib
from .compat import is_py2, compat_builtin_str, compat_str, compat_bytes
import threading
import hashlib

from .compat import compat_urlparse, compat_urljoin, compat_urlunparse, compat_urlsplit, compat_urlencode
import time
import os
import re

#imports for cookies
from .compat import CompatCookieJar as XCookieJar
from .compat import CompatCookie as XCookie
from .compat import CompatDefaultCookiePolicy as XDefaultCookiePolicy
from .compat import CompatMorsel as XMorsel
import copy
import calendar

#imports for sessions
from .compat import is_py3, compat_quote
from datetime import timedelta

#imports for models
from .compat import compat_chardet

#imports for utils
import socket
from .compat import CompatCallable as XCallable
from .compat import integer_types, compat_proxy_bypass, compat_getproxies, compat_unquote
import codecs
import zipfile
import tempfile
import struct

#imports needed for packages
try:
    import chardet as chardet_packages
except ImportError:
    import charset_normalizer as chardet_packages
    import warnings

    warnings.filterwarnings('ignore', 'Trying to detect', module='charset_normalizer')

try:
    import charset_normalizer
except ImportError:
    charset_normalizer = None

try:
    import chardet as chardet_help
except ImportError:
    chardet_help = None

try:
    from urllib3.contrib import pyopenssl
except ImportError:
    pyopenssl = None
    OpenSSL = None
    cryptography = None
else:
    import OpenSSL
    import cryptography

#imports for exceptions
from .compat import CompatJSONDecodeError as XJSONDecodeError

class XStruct:
    def unpack(self, fmt, string):
        return struct.unpack(fmt, string)

    def pack(self, param, bits):
        return struct.pack(param, bits)


class XCodecs:
    def getincrementaldecoder(self, encoding):
        return codecs.getincrementaldecoder(encoding)

    def BOM_UTF32_LE(self):
        return codecs.BOM_UTF32_LE

    def BOM_UTF32_BE(self):
        return codecs.BOM_UTF32_BE

    def BOM_UTF8(self):
        return codecs.BOM_UTF8

    def BOM_UTF16_LE(self):
        return codecs.BOM_UTF16_LE

    def BOM_UTF16_BE(self):
        return codecs.BOM_UTF16_BE


class XSocket:
    def error(self):
        return socket.error

    def inet_aton(self, a):
        return socket.inet_aton(a)

    def gaierror(self):
        return socket.gaierror

    def inet_ntoa(self, a):
        return socket.inet_ntoa(a)

    def socket(self):
        return socket.socket()


class XCopy:
    def copy(self, x):
        return copy.copy(x)


class XCalendar:
    def timegm(self, tuple):
        return calendar.timegm(tuple)


class XRe:
    def compile(self, pattern, flags=0):
        return re.compile(pattern, flags)

    def split(self, pattern, string, maxsplit=0, flags=0):
        return re.split(pattern, string, maxsplit, flags)

    def IGNORECASE(self):
        return re.IGNORECASE

    def I(self):
        return re.I

    def findall(self, pattern, string, flags=0):
        return re.findall(pattern, string, flags)


class XOs:
    def urandom(self, a):
        return os.urandom(a)

    def environ(self):
        return os.environ

    def path(self):
        return os.path

    def fstat(self, a):
        return os.fstat(a)

    def rename(self, src, dst):
        return os.rename(src, dst)

    def replace(self, file, location):
        return os.replace(file, location)

    def remove(self, path):
        return os.remove(path)

    def fdopen(self, fd, *args, **kwargs):
        return os.fdopen(fd, *args, **kwargs)

    def name(self):
        return os.name


class XDateTime:
    def timedelta(self, *args, **kwargs):
        return timedelta(*args, **kwargs)


class XUrllib3:
    def version(self):
        return urllib3.__version__

    def xpoolmanager(self):
        return urllib3.poolmanager

    def response(self):
        return urllib3.response

    def util(self):
        return urllib3.util

    def exceptions(self):
        return urllib3.exceptions

    def SOCKSProxyManager(self, *args, **kwargs):
        try:
            from urllib3.contrib.socks import SOCKSProxyManager
            return SOCKSProxyManager(*args, **kwargs)
        except ImportError:
            return None

    def fields(self):
        return urllib3.fields

    def filepost(self):
        return urllib3.filepost


class XTime:
    def ctime(self):
        return time.ctime()

    def time(self):
        return time.time()

    def strptime(self, string, format):
        return time.strptime(string, format)

    # Preferred clock, based on which one is more accurate on a given system.
    def clock_method(self):
        if sys.platform == 'win32':
            try:  # Python 3.4+
                preferred_clock = time.perf_counter
            except AttributeError:  # Earlier than Python 3.
                preferred_clock = time.clock
        else:
            preferred_clock = time.time
        return preferred_clock


class XHashLib:
    def sha256(self, a):
        return hashlib.sha256(a)

    def md5(self, a):
        return hashlib.md5(a)

    def sha1(self, a):
        return hashlib.sha1(a)

    def sha512(self, a):
        return hashlib.sha512(a)


class XThreading:
    def local(self):
        return threading.local()

    def RLock(self, verbose=None):
        return threading.RLock(verbose)

class XCompat:
    def is_py2(self):
        return is_py2

    def is_builtin_str_instance(self,string):
        return isinstance(string, compat_builtin_str)

    def urlparse(self, url, scheme='', allow_fragments=True):
        return compat_urlparse(url, scheme, allow_fragments)

    def urlsplit(self, url, scheme='', allow_fragments=True):
        return compat_urlsplit(url, scheme, allow_fragments)

    def urljoin(self, base, url, allow_fragments=True):
        return compat_urljoin(base, url, allow_fragments)

    def urlencode(self, query, doseq=0):
        return compat_urlencode(query, doseq)

    def urlunparse(self, a):
        return compat_urlunparse(a)

    def is_py3(self):
        return is_py3

    def quote(self, s, safe='/'):
        return compat_quote(s, safe)

    def unquote(self, s):
        return compat_unquote(s)

    def integer_types(self):
        return integer_types

    def is_Callable_instance(self, value):
        return isinstance(value, XCallable)

    def str_class(self):
        return compat_str

    def is_str_instance(self,string):
        return isinstance(string, compat_str)

    def bytes_class(self):
        return compat_bytes

    def is_bytes_instance(self,string):
        return isinstance(string, compat_bytes)

    def builtin_str_class(self):
        return compat_builtin_str

    def builtin_str(self, x):
        return compat_builtin_str(x)

    def basestring_class(self):
        return conpat_basestring

    def is_basestring_instance(self, string):
        return isinstance(string, conpat_basestring)

    def str(self, *args, **kwargs):
        return compat_str(*args, **kwargs)

    def proxy_bypass(self, a):
        return compat_proxy_bypass(a)

    def getproxies(self):
        return compat_getproxies()

    def chardet(self):
        return compat_chardet


class XBase64:
    def b64encode(self, s, altchars=None):
        return b64encode(s, altchars)


class XWarnings:
    def warn(self, *args, **kwargs):
        return warnings.warn(*args, **kwargs)


class PyPyVersionInfo:
    def major(self):
        return sys.pypy_version_info.major

    def minor(self):
        return sys.pypy_version_info.minor

    def micro(self):
        return sys.pypy_version_info.micro

    def releaselevel(self):
        return sys.releaselevel.micro


class XCharDet:
    def __init__(self, original_source_file_name):
        if original_source_file_name == 'help.py':
            self.chardet = chardet_help
        elif original_source_file_name == 'compat.py':
            self.chardet = compat_chardet
        elif original_source_file_name == 'packages.py':
            self.chardet = chardet_packages


    def import_works(self):
        return self.chardet is not None

    def version(self):
        return self.chardet.__version__

    def detect(self, x):
        return self.chardet.detect(x)

    def name(self):
        return self.chardet.__name__


class XCharSetNormalizer:
    def import_works(self):
        return charset_normalizer is not None

    def version(self):
        return charset_normalizer.__version__


class XCryptography:
    def version(self):
        return getattr(cryptography, '__version__', '')


class XIo:
    def UnsupportedOperation(self):
        return io.UnsupportedOperation


class XIdna:
    def version(self):
        return getattr(idna, '__version__', '')

    def encode(self, s, strict=False, uts46=False, std3_rules=False, transitional=False):
        return idna.encode(s, strict, uts46, std3_rules, transitional)

    def IDNAError(self):
        return idna.IDNAError


class XJson:
    def dumps(self, obj, indent=None, sort_keys=False):
        return json.dumps(obj, sort_keys, indent)


class XOpenSSL:
    def import_works(self):
        return OpenSSL is not None

    def version(self):
        return OpenSSL.__version__

    def openssl_version(self):
        return OpenSSL.SSL.OPENSSL_VERSION_NUMBER


class XPlatform:
    def system(self):
        return platform.system()

    def release(self):
        return platform.release()

    def python_implementation(self):
        return platform.python_implementation()

    def python_version(self):
        pass


class XPyOpenSsl:
    def import_works(self):
        return pyopenssl is not None


class XSsl:
    def openssl_version(self):
        return ssl.OPENSSL_VERSION_NUMBER


class XSys:
    def pypy_version_info(self):
        return PyPyVersionInfo

    def platform(self):
        return sys.platform

    def version_info(self):
        return sys.version_info

    def modules(self):
        return sys.modules


class XTempFile:
    def gettempdir(self):
        return tempfile.gettempdir()

    def mkstemp(self, suffix="", prefix=tempfile.template, dir=None, text=False):
        return tempfile.mkstemp(suffix, prefix, dir, text)

    def template(self):
        return tempfile.template


if XSys().platform() == 'win32':


    class XWinReg:
        def __init__(self):
            try:
                if XCompat().is_py3():
                    import winreg
                else:
                    import _winreg as winreg
                return winreg

            except ImportError:
                return False




class XZipfile:
    def ZipFile(self, file):
        return zipfile.ZipFile(file)

    def is_zipfile(self, filename):
        return zipfile.is_zipfile(filename)

class XCookieJarRequest:
    """Wraps a `requests.Request` to mimic the request used by http.cookiejar.py

    The code in `cookielib.CookieJar` expects this interface in order to correctly
    manage cookie policies, i.e., determine whether a cookie can be set, given the
    domains of the request and the cookie.

    The original request object is read-only. The client is responsible for collecting
    the new headers via `added_headers()` and interpreting them appropriately. You
    probably want `Cookies().get_cookie_header`, defined below.
    """

    def __init__(self, request):
        self._r = request
        self._new_headers = {}
        self.type = XCompat().urlparse(self._r.url_()).scheme

    def get_host(self):  # not called but needed py py2
        return XCompat().urlparse(self._r.url_()).netloc

    def get_origin_req_host(self):  # needed by cookielib.py (python2.7)
        return XCompat().urlparse(self._r.url_()).netloc
        # return self.get_host()

    def get_full_url(self):  # needed by http.cookiejar.py
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self._r.headers_().get('Host'):
            return self._r.url_()
        # If they did set it, retrieve it and reconstruct the expected domain
        host = XUtils().to_native_string(self._r.headers_()['Host'], encoding='utf-8')
        parsed = XCompat().urlparse(self._r.url_())
        # Reconstruct the URL as we expect it
        return XCompat().urlunparse([
            parsed.scheme, host, parsed.path, parsed.params, parsed.query,
            parsed.fragment
        ])

    def is_unverifiable(self):  # needed by cookielib.py (python2.7)
        return True

    def has_header(self, name):  # needed by http.cookiejar.py
        return name in self._r.headers_() or name in self._new_headers

    def get_header(self, name, default=None):  # not called but needed py py2
        return self._r.headers_().get(name, self._new_headers.get(name, default))

    def add_unredirected_header(self, name, value):  # needed by http.cookiejar.py
        self._new_headers[name] = value

    def added_headers(self): # needed by Cookies().get_cookie_header
        return self._new_headers

    @property
    def unverifiable(self):  # needed by http.cookiejar.py
        return self.is_unverifiable()

    @property
    def origin_req_host(self):  # needed by http.cookiejar.py
        return self.get_origin_req_host()

    @property
    def host(self):
        return self.get_host()


class XCookieJarResponse:
    """Wraps a `httplib.HTTPMessage` to mimic a `urllib.addinfourl`.

    ...what? Basically, expose the parsed HTTP headers from the server response
    the way `cookielib` expects to see them.
    """

    def __init__(self, headers):
        """Make a MockResponse for `cookielib` to read.

        :param headers: a httplib.HTTPMessage or analogous carrying the headers
        """
        self._headers = headers

    def info(self):  # needed by http.cookiejar.py
        return self._headers


class XUtils:  # ./InternalUtils/internal_utils.py
    """
    requests._internal_utils
    ~~~~~~~~~~~~~~

    Provides utility functions that are consumed internally by Requests
    which depend on extremely few external helpers (such as compat)
    """

    def to_native_string(self, string, encoding='ascii'):  # ./InternalUtils/internal_utils.py
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

    def unicode_is_ascii(self, u_string):  # ./InternalUtils/internal_utils.py
        """Determine if unicode string only contains ASCII characters.

        :param str u_string: unicode string to check. Must be unicode
            and not Python 2 `str`.
        :rtype: bool
        """
        assert XCompat().is_str_instance(u_string)
        try:
            u_string.encode('ascii')
            return True
        except UnicodeEncodeError:
            return False

    def get_or_set(self, instance, variable, *args):
        if len(args) != 0:
            setattr(instance, variable, args[0])
            return instance
        return getattr(instance, variable)