# -*- coding: utf-8 -*-
from .domain import Requests

def request(method, url, **kwargs):
    return Requests().request(method, url, **kwargs)

def get(url, params=None, **kwargs):
    return Requests().get(url, params, **kwargs)

def options(url, **kwargs):
    return Requests().options(url, **kwargs)

def head(url, **kwargs):
    return Requests().head(url, **kwargs)

def post(url, data=None, json=None, **kwargs):
    return Requests().post(url, data, json, **kwargs)

def put(url, data=None, **kwargs):
    return Requests().put(url, data, **kwargs)

def patch(url, data=None, **kwargs):
    return Requests().patch(url, data, **kwargs)

def delete(url, **kwargs):
    return Requests().delete(url, **kwargs)
