# -*- coding: utf-8 -*-

from requests.compat import is_py3


try:
    import StringIO as CompatStringIO
except ImportError:
    import io as CompatStringIO

try:
    from cStringIO import StringIO as Compat_cStringIO
except ImportError:
    Compat_cStringIO = None

if is_py3:
    def u(s):
        return s
else:
    def u(s):
        return s.decode('unicode-escape')
