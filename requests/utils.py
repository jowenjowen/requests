# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utility functions that are used within Requests
that are also useful for external consumption.
These functions have been moved to the .domain.Utils class - see documentation there
This file only exists for compatibility for external users
"""
import contextlib
from .domain import Utils
from .domain import CookieUtils

def proxy_bypass(host):
    return Utils().proxy_bypass(host)

def dict_to_sequence(d):
    return Utils().dict_to_sequence(d)

def super_len(o):
    return Utils().super_len(o)

def get_netrc_auth(url, raise_errors=False):
    return Utils().get_netrc_auth(url, raise_errors)

def guess_filename(obj):
    return Utils().guess_filename(obj)

def extract_zipped_paths(path):
    return Utils().extract_zipped_paths(path)

@contextlib.contextmanager
def atomic_open(filename):
    return Utils().atomic_open(filename)

def from_key_val_list(value):
    return Utils().from_key_val_list(value)

def to_key_val_list(value):
    return Utils().to_key_val_list(value)

def parse_list_header(value):
    return Utils().parse_list_header(value)

def parse_dict_header(value):
    return Utils().parse_dict_header(value)

def unquote_header_value(value, is_filename=False):
    return Utils().unquote_header_value(value, is_filename)

def dict_from_cookiejar(cj):
    return CookieUtils().dict_from_cookiejar(cj)

def add_dict_to_cookiejar(cj, cookie_dict):
    return CookieUtils().add_dict_to_cookiejar(cj, cookie_dict)

def get_encodings_from_content(content):
    return Utils().get_encodings_from_content(content)

def get_encoding_from_headers(headers):
    return Utils().get_encoding_from_headers(headers)

def stream_decode_response_unicode(iterator, r):
    return Utils().stream_decode_response_unicode(iterator, r.encoding_())

def iter_slices(string, slice_length):
    return Utils().iter_slices(string, slice_length)

def get_unicode_from_response(r):
    return Utils().get_unicode_from_response(r)

def unquote_unreserved(uri):
    return Utils().unquote_unreserved(uri)

def requote_uri(uri):
    return Utils().requote_uri(uri)

def address_in_network(ip, net):
    return Utils().address_in_network(ip, net)

def dotted_netmask(mask):
    return Utils().dotted_netmask(mask)

def is_ipv4_address(string_ip):
    return Utils().is_ipv4_address(string_ip)

def is_valid_cidr(string_network):
    return Utils().is_valid_cidr(string_network)

def set_environ(env_name, value):
    return Utils().set_environ(env_name, value)

def should_bypass_proxies(url, no_proxy):
    return Utils().should_bypass_proxies(url, no_proxy)

def get_environ_proxies(url, no_proxy=None):
    return Utils().get_environ_proxies(url, no_proxy)

def select_proxy(url, proxies):
    return Utils().select_proxy(url, proxies)

def resolve_proxies(request, proxies, trust_env=True):
    return Utils().resolve_proxies(request, proxies, trust_env)

def default_user_agent(name="python-requests"):
    return Utils().default_user_agent(name)

def default_headers():
    return Utils().default_headers()

def parse_header_links(value):
    return Utils().parse_header_links(value)

def guess_json_utf(data):
    return Utils().guess_json_utf(data)

def prepend_scheme_if_needed(url, new_scheme):
    return Utils().prepend_scheme_if_needed(url, new_scheme)

def get_auth_from_url(url):
    return Utils().get_auth_from_url(url)

def check_header_validity(header):
    return Utils().check_header_validity(header)

def urldefragauth(url):
    return Utils().urldefragauth(url)

def rewind_body(prepared_request):
    return Utils().rewind_body(prepared_request)