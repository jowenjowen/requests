# x.py contains all the external libraries used wrapped in objects
import json
import platform
import ssl
import sys

import idna
import urllib3

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


