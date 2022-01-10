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
from .domain import ProxyUtils
from .domain import CollectionsUtils
from .domain import FileUtils
from .domain import WSGIutils
from .domain import CookieUtils
from .domain import HeaderUtils
from .domain import IpUtils
from .domain import UrlUtils

def proxy_bypass(host):
    return ProxyUtils().proxy_bypass(host)

def dict_to_sequence(d):
    return DeprecatedCollectionsUtils().dict_to_sequence(d)

def super_len(o):
    return Utils().super_len(o)

def get_netrc_auth(url, raise_errors=False):
    return UrlUtils().get_netrc_auth(url, raise_errors)

def guess_filename(obj):
    return FileUtils().guess_filename(obj)

def extract_zipped_paths(path):
    return Utils().extract_zipped_paths(path)

@contextlib.contextmanager
def atomic_open(filename):
    return FileUtils().atomic_open(filename)

def from_key_val_list(value):
    return DeprecatedCollectionsUtils().from_key_val_list(value)

def to_key_val_list(value):
    return CollectionsUtils().to_key_val_list(value)

def parse_list_header(value):
    return DeprecatedWSGIutils().parse_list_header(value)

def parse_dict_header(value):
    return WSGIutils().parse_dict_header(value)

def unquote_header_value(value, is_filename=False):
    return WSGIutils().unquote_header_value(value, is_filename)

def dict_from_cookiejar(cj):
    return CookieUtils().dict_from_cookiejar(cj)

def add_dict_to_cookiejar(cj, cookie_dict):
    return CookieUtils().add_dict_to_cookiejar(cj, cookie_dict)

def get_encodings_from_content(content):
    return Utils().get_encodings_from_content(content)

def get_encoding_from_headers(headers):
    return HeaderUtils().get_encoding_from_headers(headers)

def stream_decode_response_unicode(iterator, r):
    return Utils().stream_decode_response_unicode(iterator, r.encoding_())

def iter_slices(string, slice_length):
    return Utils().iter_slices(string, slice_length)

def get_unicode_from_response(r):
    return Utils().get_unicode_from_response(r)

def unquote_unreserved(uri):
    return UrlUtils().unquote_unreserved(uri)

def requote_uri(uri):
    return UrlUtils().requote_uri(uri)

def address_in_network(ip, net):
    return ProxyUtils().address_in_network(ip, net)

def dotted_netmask(mask):
    return ProxyUtils().dotted_netmask(mask)

def is_ipv4_address(string_ip):
    return IpUtils().is_ipv4_address(string_ip)

def is_valid_cidr(string_network):
    return ProxyUtils().is_valid_cidr(string_network)

def set_environ(env_name, value):
    return Utils().set_environ(env_name, value)

def should_bypass_proxies(url, no_proxy):
    return ProxyUtils().should_bypass_proxies(url, no_proxy)

def get_environ_proxies(url, no_proxy=None):
    return ProxyUtils().get_environ_proxies(url, no_proxy)

def select_proxy(url, proxies):
    return ProxyUtils().select_proxy(url, proxies)

def resolve_proxies(request, proxies, trust_env=True):
    return ProxyUtils().resolve_proxies(request, proxies, trust_env)

def default_user_agent(name="python-requests"):
    return HeaderUtils().default_user_agent(name)

def default_headers():
    return HeaderUtils().default_headers()

def parse_header_links(value):
    return HeaderUtils().parse_header_links(value)

def guess_json_utf(data):
    return Utils().guess_json_utf(data)

def prepend_scheme_if_needed(url, new_scheme):
    return UrlUtils().prepend_scheme_if_needed(url, new_scheme)

def get_auth_from_url(url):
    return UrlUtils().get_auth_from_url(url)

def check_header_validity(header):
    return HeaderUtils().check_header_validity(header)

def urldefragauth(url):
    return UrlUtils().urldefragauth(url)

def rewind_body(prepared_request):
    return FileUtils().rewind_body(prepared_request)

class DeprecatedCollectionsUtils:  # ./Utils/collections_utils.py
    def dict_to_sequence(self, d):  # ./Utils/utils.py
        """Returns an internal sequence dictionary update."""

        if hasattr(d, 'items'):
            d = d.items()

        return d

    def from_key_val_list(self, value):  # ./Utils/utils.py
        """Take an object and test to see if it can be represented as a
        dictionary. Unless it can not be represented as such, return an
        OrderedDict, e.g.,

        ::

            >>> from_key_val_list([('key', 'val')])
            OrderedDict([('key', 'val')])
            >>> from_key_val_list('string')
            Traceback (most recent call last):
            ...
            ValueError: cannot encode objects that are not 2-tuples
            >>> from_key_val_list({'key': 'val'})
            OrderedDict([('key', 'val')])

        :rtype: OrderedDict
        """
        if value is None:
            return None

        if isinstance(value, (str, bytes, bool, int)):
            raise ValueError('cannot encode objects that are not 2-tuples')

        return XOrderedDict(value)


class DeprecatedWSGIutils:  # ./Utils/wsgi_utils.py
    # From mitsuhiko/werkzeug (used with permission).
    def parse_list_header(self, value):  # ./Utils/utils.py
        """Parse lists as described by RFC 2068 Section 2.

        In particular, parse comma-separated lists where the elements of
        the list may include quoted-strings.  A quoted-string could
        contain a comma.  A non-quoted string could have quotes in the
        middle.  Quotes are removed automatically after parsing.

        It basically works like :func:`parse_set_header` just that items
        may appear multiple times and case sensitivity is preserved.

        The return value is a standard :class:`list`:

        >>> parse_list_header('token, "quoted value"')
        ['token', 'quoted value']

        To create a header from the :class:`list` again, use the
        :func:`dump_header` function.

        :param value: a string with a list header.
        :return: :class:`list`
        :rtype: list
        """
        result = []
        for item in _parse_list_header(value):
            if item[:1] == item[-1:] == '"':
                item = self.unquote_header_value(item[1:-1])
            result.append(item)
        return result

