# -*- coding: utf-8 -*-
from .domain import Requests
from .domain import Session
from .domain import Request
from .domain import Response
import requests.exceptions

from requests.exceptions import HTTPError as HTTPErrorUnused
class DummyClass1:
    HTTPError = HTTPErrorUnused
exceptions = DummyClass1()

from requests.domain import CookieJar as RequestsCookieJarUnused
class DummyClass2:
    RequestsCookieJar = RequestsCookieJarUnused
cookies = DummyClass2()

from requests.utils import get_netrc_auth as get_netrc_auth_unused
class DummyClass3:
    get_netrc_auth = get_netrc_auth_unused
sessions = DummyClass3()


def session():
    return Session()

def request(method, url, **kwargs):
    return Requests().request(method, url, **kwargs)

def get(url, params=None, **kwargs):
    return Requests().url_(url).params_(params).get(**kwargs)

def options(url, **kwargs):
    return Requests().url_(url).options(**kwargs)

def head(url, **kwargs):
    return Requests().url_(url).head(**kwargs)

def post(url, data=None, json=None, **kwargs):
    return Requests().url_(url).data_(data).json_(json).post(**kwargs)

def put(url, data=None, **kwargs):
    return Requests().url_(url).data_(data).put(**kwargs)

def patch(url, data=None, **kwargs):
    return Requests().url_(url).data_(data).patch(**kwargs)

def delete(url, **kwargs):
    return Requests().url_(url).delete(**kwargs)
