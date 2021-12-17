# -*- coding: utf-8 -*-
from .domain import Api

def request(method, url, **kwargs):
    return Api().request(method, url, **kwargs)

def get(url, params=None, **kwargs):
    return Api().get(url, params, **kwargs)

def options(url, **kwargs):
    return Api().options(url, **kwargs)

def head(url, **kwargs):
    return Api().head(url, **kwargs)

def post(url, data=None, json=None, **kwargs):
    return Api().post(url, data, json, **kwargs)

def put(url, data=None, **kwargs):
    return Api().put(url, data, **kwargs)

def patch(url, data=None, **kwargs):
    return Api().patch(url, data, **kwargs)

def delete(url, **kwargs):
    return Api().delete(url, **kwargs)
