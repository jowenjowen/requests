# -*- coding: utf-8 -*-

# *************************** classes in Sessions section *****************
"""
requests.sessions
~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).
"""
from .domain import Session as DomainSession

def session():
    return Session()


class Session:
    def __init__(self):
        self.domain_class = DomainSession()

    def __enter__(self):
        return self.domain_class.__enter__()

    def __exit__(self, *args):
        return self.domain_class.__exit__(*args)

    def prepare_request(self, request):
        return self.domain_class.prepare_request(request)

    def request(self, method, url,
            params=None, data=None, headers=None, cookies=None, files=None,
            auth=None, timeout=None, allow_redirects=True, proxies=None,
            hooks=None, stream=None, verify=None, cert=None, json=None):
        return self.domain_class.request(method, url,
            params, data, headers, cookies, files,
            auth, timeout, allow_redirects, proxies,
            hooks, stream, verify, cert, json)

    def get(self, url, **kwargs):
        return self.domain_class.get(url, **kwargs)

    def options(self, url, **kwargs):
        return self.domain_class.options(url, **kwargs)

    def head(self, url, **kwargs):
        return self.domain_class.head(url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.domain_class.post(url, data, json, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.domain_class.put(url, data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        return self.domain_class.patch(url, data=None, **kwargs)

    def delete(self, url, **kwargs):
        return self.domain_class.delete(url, **kwargs)

    def send(self, request, **kwargs):
        return self.domain_class.send(request, **kwargs)

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        return self.domain_class.merge_environment_settings(url, proxies, stream, verify, cert)

    def get_adapter(self, url):
        return self.domain_class.get_adapter(url)

    def close(self):
        return self.domain_class.close()

    def mount(self, prefix, adapter):
        return self.domain_class.mount(prefix, adapter)

    def __getstate__(self):
        return self.domain_class.__getstate__()

    def __setstate__(self, state):
        return self.domain_class.__setstate__(state)
