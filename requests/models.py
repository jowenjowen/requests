# -*- coding: utf-8 -*-

# *************************** classes in Models section *****************
"""
requests.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power Requests.
"""
from .domain import DRequest as DomainRequest
from .domain import DPreparedRequest as DomainPreparedRequest
from .domain import DResponse as DomainResponse
ITER_CHUNK_SIZE = 512

class RequestEncodingMixin(object):
    @property
    def path_url(self):
        return 5

    @staticmethod
    def _encode_params(data):
        return 5

    @staticmethod
    def _encode_files(files, data):
        return 5


class RequestHooksMixin(object):
    def register_hook(self, event, hook):
        return 5


class Request(RequestHooksMixin):
    def __init__(self,
            method=None, url=None, headers=None, files=None, data=None,
            params=None, auth=None, cookies=None, hooks=None, json=None):
        self.domain_class_ = DomainRequest(self,
            method, url, headers, files, data,
            params, auth, cookies, hooks, json)

    def __repr__(self):
        return self.domain_class_.__repr__()

    def prepare(self):
        return self.domain_class_.prepare()

    def domain_class(self):
        return self.domain_class_

class PreparedRequest(RequestEncodingMixin, RequestHooksMixin):
    def __init__(self):
        self.domain_class = DomainPreparedRequest(self)

    def prepare(self,
            method=None, url=None, headers=None, files=None, data=None,
            params=None, auth=None, cookies=None, hooks=None, json=None):
        self.domain_class(self,
            method, url, headers, files, data,
            params, auth, cookies, hooks, json)
        return self

    def __repr__(self):
        return self.domain_class.__repr__()

    def copy(self):
        return self.domain_class.copy()

    def prepare_method(self, method):
        return self.domain_class.prepare_method(method)

    def prepare_url(self, url, params):
        return self.domain_class.prepare_url(url, params)

    def prepare_headers(self, headers):
        return self.domain_class.prepare_headers(headers)

    def prepare_body(self, data, files, json=None):
        return self.domain_class.prepare_body(data, files, json)

    def prepare_content_length(self, body):
        return self.domain_class.prepare_content_length(body)

    def prepare_auth(self, auth, url=''):
        return self.domain_class.prepare_auth(auth, url)

    def prepare_cookies(self, cookies):
        return self.domain_class.prepare_cookies(cookies)

    def prepare_hooks(self, hooks):
        return self.domain_class.prepare_hooks(hooks)


class Response:
    def __init__(self):
        self.domain_class = DomainResponse(self)

    def __enter__(self):
        return self.__enter__()

    def __exit__(self, *args):
        self.domain_class.__exit__()

    def __getstate__(self):
        return self.domain_class.__getstate__()

    def __setstate__(self, state):
        return self.domain_class.__setstate__()

    def __repr__(self):
        return self.domain_class.__repr__(0)

    def __bool__(self):
        return self.domain_class.__bool__()

    def __nonzero__(self):
        return self.domain_class.__nonzero__()

    def __iter__(self):
        return self.domain_class.__iter__()

    @property
    def ok(self):
        return self.domain_class.ok()

    @property
    def is_redirect(self):
        return self.domain_class.is_redirect()

    @property
    def is_permanent_redirect(self):
        return self.domain_class.is_permanent_redirect()

    @property
    def next(self):
        return self.domain_class.next()

    @property
    def apparent_encoding(self):
        return self.domain_class.apparent_encoding()

    def iter_content(self, chunk_size=1, decode_unicode=False):
        return self.domain_class.iter_content(chunk_size, decode_unicode)

    def iter_lines(self, chunk_size=ITER_CHUNK_SIZE, decode_unicode=False, delimiter=None):
        return self.domain_class.iter_lines(chunk_size, decode_unicode, delimiter)

    @property
    def content(self):
        return self.domain_class.content()

    @property
    def text(self):
        return self.domain_class.text()

    def json(self, **kwargs):
        return self.domain_class.json(**kwargs)

    @property
    def links(self):
        return self.domain_class.links()

    def raise_for_status(self):
        return self.domain_class.raise_for_status()

    def close(self):
        return self.domain_class.close()
