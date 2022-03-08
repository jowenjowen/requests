# -*- coding: utf-8 -*-


try:
    import StringIO as CompatStringIO
except ImportError:
    import io as CompatStringIO

try:
    from cStringIO import StringIO as Compat_cStringIO
except ImportError:
    Compat_cStringIO = None

def u(s):
    return s
