# -*- coding: utf-8 -*-
from .domain import Requests

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
