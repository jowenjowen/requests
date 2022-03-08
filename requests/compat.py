# -*- coding: utf-8 -*-

"""
requests.compat
~~~~~~~~~~~~~~~

This module handles import compatibility issues between Python 2 and
Python 3.
"""

try:
    import chardet as compat_chardet
except ImportError:
    import charset_normalizer as compat_chardet

import sys

# -------
# Pythons
# -------

# Syntax sugar.
_ver = sys.version_info

has_simplejson = False
try:
    import simplejson as compat_json
    has_simplejson = True
except ImportError:
    import json as compat_json

# ---------
# Specifics
# ---------

from urllib.parse import quote as compat_quote
from urllib.parse import unquote as compat_unquote
from urllib.parse import quote_plus as compat_quote_plus
from urllib.parse import unquote_plus as compat_unquote_plus
from urllib.parse import urlencode as compat_urlencode
from urllib.request import getproxies as compat_getproxies
from urllib.request import proxy_bypass as compat_proxy_bypass
from urllib.request import proxy_bypass_environment as compat_proxy_bypass_environment
from urllib.request import getproxies_environment as compat_getproxies_environment
from urllib.parse import urlparse as compat_urlparse
from urllib.parse import urlunparse as compat_urlunparse
from urllib.parse import urljoin as compat_urljoin
from urllib.parse import urlsplit as compat_urlsplit
from urllib.parse import urldefrag as compat_urldefrag
from urllib.request import parse_http_list as compat_parse_http_list
import http.cookiejar as compat_cookielib
from http.cookiejar import CookieJar as CompatCookieJar
from http.cookiejar import Cookie as CompatCookie
from http.cookiejar import DefaultCookiePolicy as CompatDefaultCookiePolicy
from http.cookies import Morsel as CompatMorsel
from io import StringIO as CompatStringIO
# Keep OrderedDict for backwards compatibility.
from collections import OrderedDict as CompatOrderedDict
from collections.abc import Callable as CompatCallable
from collections.abc import Mapping as CompatMapping
from collections.abc import MutableMapping as CompatMutableMapping
if has_simplejson:
    from simplejson import JSONDecodeError as CompatJSONDecodeError
else:
    from json import JSONDecodeError as CompatJSONDecodeError

compat_builtin_str = str
compat_str = str
compat_bytes = bytes
conpat_basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)
