# x.py contains all the external libraries used wrapped in objects
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
from .compat import is_py2, builtin_str, str
import threading
import hashlib

from .compat import urlparse
import time
import os
import re

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


class XRe:
    def compile(self, pattern, flags=0):
        return re.compile(pattern, flags)

    def IGNORECASE(self):
        return re.IGNORECASE


class XOs:
    def urandom(self, a):
        return os.urandom(a)


class XTime:
    def ctime(self):
        return time.ctime()


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


class XCompat:
    def is_py2(self):
        return is_py2

    def is_builtin_str_instance(self,string):
        return isinstance(string, builtin_str)

    def urlparse(self, a):
        return urlparse(a)


class XBase64:
    def b64encode(self, s, altchars=None):
        return b64encode(s, altchars)


class XWarnings:
    def warn(self, *args, **kwargs):
        return warnings.warn(*args, **kwargs)


class XBaseString:
    def type(self):
        return basestring


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


class XCharSetNormalizer:
    def import_works(self):
        return charset_normalizer is not None

    def version(self):
        return charset_normalizer.__version__


class XCryptography:
    def version(self):
        return getattr(cryptography, '__version__', '')


class XIdna:
    def version(self):
        return getattr(idna, '__version__', '')


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
