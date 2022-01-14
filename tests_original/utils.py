# -*- coding: utf-8 -*-

import contextlib
from requests.five_d.x import XOs


@contextlib.contextmanager
def override_environ(**kwargs):
    save_env = dict(XOs().environ())
    for key, value in kwargs.items():
        if value is None:
            del XOs().environ()[key]
        else:
            XOs().environ()[key] = value
    try:
        yield
    finally:
        XOs().environ().clear()
        XOs().environ().update(save_env)
