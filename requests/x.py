# x.py contains all the external libraries used wrapped in objects
import io
import json
import platform
import ssl
import sys

import idna
import urllib3
from collections import OrderedDict as XOrderedDict
from .compat import Mapping as XMapping
from .compat import MutableMapping as XMutableMapping
from .compat import basestring
import warnings
from base64 import b64encode

# imports for XWarnings, XBase64, XCompat, XThreading, XHashLib
from .compat import is_py2, builtin_str, str, bytes
import threading
import hashlib

from .compat import urlparse, urljoin, urlunparse, urlsplit, urlencode
import time
import os
import re

#imports for cookies
from .compat import cookielib
from .compat import Morsel as XMorsel
import copy
import calendar

#imports for sessions
from .compat import is_py3, quote
from datetime import timedelta

#imports for utils
import socket
from .compat import integer_types
import codecs

try:
    import charset_normalizer
except ImportError:
    charset_normalizer = None

try:
    import chardet
except ImportError:
    chardet = None

try:
    from urllib3.contrib import pyopenssl
except ImportError:
    pyopenssl = None
    OpenSSL = None
    cryptography = None
else:
    import OpenSSL
    import cryptography


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


class XSocket:
    def error(self):
        return socket.error

    def inet_aton(self, a):
        return socket.inet_aton(a)

class XCopy:
    def copy(self, x):
        return copy.copy(x)


class XCalendar:
    def timegm(self, tuple):
        return calendar.timegm(tuple)


class XRe:
    def compile(self, pattern, flags=0):
        return re.compile(pattern, flags)

    def IGNORECASE(self):
        return re.IGNORECASE


class XOs:
    def urandom(self, a):
        return os.urandom(a)

    def environ(self, a):
        return os.environ

    def path(self):
        return os.path

    def fstat(self, a):
        return os.fstat(a)

class XDateTime:
    def timedelta(self, a):
        return timedelta(a)


class XUrllib3:
    def fields(self):
        return urllib3.fields

    def filepost(self):
        return urllib3.filepost

    def exceptions(self):
        return urllib3.exceptions

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
        return isinstance(string, builtin_str)

    def urlparse(self, a):
        return urlparse(a)

    def urlsplit(self, url, scheme='', allow_fragments=True):
        return urlsplit(url, scheme, allow_fragments)

    def urljoin(self, base, url, allow_fragments=True):
        return urljoin(base, url, allow_fragments)

    def urlencode(self):
        return urlencode()

    def urlunparse(self, a):
        return urlunparse(a)

    def cookielib(self):
        return cookielib

    def is_py3(self):
        return is_py3

    def quote(self):
        return quote

    def integer_types(self):
        return integer_types

    def Callable(self):
        return Callable

    def str_class(self):
        return str

    def is_str_instance(self,string):
        return isinstance(string, str)

    def bytes_class(self):
        return bytes

    def is_bytes_instance(self,string):
        return isinstance(string, bytes)

    def builtin_str_class(self):
        return bytes

    def builtin_str(self, x):
        return builtin_str(x)

    def basestring_class(self):
        return basestring

    def is_basestring_instance(self, string):
        return isinstance(string, basestring)

    def str(self, a):
        return str(a)


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
    def import_works(self):
        return chardet is not None

    def version(self):
        return chardet.__version__

    def detect(self, x):
        return chardet.detect(x)


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


class XUrllib3:
    def version(self):
        return urllib3.__version__
