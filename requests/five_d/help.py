# coding=utf-8

class Help:
    def display(self, name):
        print('----------------')
        print(name)
        print(eval('self.%s().msg()' % name))
        print('----------------')


    class Help:
        def msg(self): return '''
Refactored version of requests. Best run in a REPL (IDLE 3 is built in to the mac)
Start by pasting the following:
    requests.domain.CaseInsensitiveDict().help()
'''


    class CaseInsensitiveDict:
        def msg(self): return '''
    A case-insensitive ``dict``-like object.
    
    Implements all methods and operations of
    ``MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.
    
    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::
    
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True
    
    For example, ``headers_()['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.
    
    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.lower()``s, the
    behavior is undefined.

* method __setitem__
    # Use the lowercased key for lookups, but store the actual
    # key alongside the value.
'''


    class LookupDict:
        def msg(self): return '''
    Dictionary lookup object.
'''


    class StatusCodes:  # ./StatusCodes/status_codes.py
        def msg(self): return '''
    The ``codes`` object defines a mapping from common names for HTTP statuses
    to their numerical codes, accessible either as attributes or as dictionary
    items.

    Example::

        >>> import requests
        >>> requests.codes['temporary_redirect']
        307
        >>> requests.codes.teapot
        418
        >>> requests.codes['\o/']
        200

    Some codes have multiple names, and both upper- and lower-case versions of
    the names are allowed. For example, ``codes.ok``, ``codes.OK``, and
    ``codes.okay`` all correspond to the HTTP status code 200.
    '''

    class Connections:  # ./Connections/connections.py
        def msg(self): return '''
    requests.adapters
    ~~~~~~~~~~~~~~~~~

    This module contains the transport adapters that Requests uses to define
    and maintain xconnections.
'''

    class BaseConnections:  # ./Connections/BaseConnections.py
        def msg(self): return '''
    The Base Transport Connection
• method send
    Sends PreparedRequest object. Returns Response object.

    :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
    :param stream: (optional) Whether to stream the request content.
    :param timeout: (optional) How long to wait for the server to send
        data before giving up, as a float, or a :ref:`(connect timeout,
        read timeout) <timeouts>` tuple.
    :type timeout: float or tuple
    :param verify: (optional) Either a boolean, in which case it controls whether we verify
        the server's TLS certificate, or a string, in which case it must be a path
        to a CA bundle to use
    :param cert: (optional) Any user-provided SSL certificate to be trusted.
    :param proxies: (optional) The proxies dictionary to apply to the request.
'''

    class HTTPconnections:  # ./Connections/HTTPconnections.py
        def msg(self): return '''

The built-in HTTP Connection for urllib3.

    Provides a general-case interface for Requests sessions to contact HTTP and
    HTTPS urls by implementing the Transport Connection interface. This class will
    usually be created by the :class:`Session <Session>` class under the
    covers.

    :param xpool_connections: The number of xconnection xpools to cache.
    :param pool_maxsize: The maximum number of xconnections to save in the xpool.
    :param max_retries: The maximum number of retries each xconnection
        should attempt. Note, this applies only to failed DNS lookups, socket
        xconnections and xconnection timeouts, never to requests where data has
        made it to the server. By default, Requests does not retry failed
        xconnections. If you need granular control over the conditions under
        which we retry a request, import urllib3's ``Retry`` class and pass
        that instead.
    :param pool_block: Whether the xconnection xpool should block for xconnections.

    Usage::

      >>> import requests
      >>> s = requests.Session()
      >>> a = requests.adapters.HTTPconnections(max_retries=3)
      >>> s.mount('http://', a)

• method __setstate__
    # Can't handle by adding 'proxy_manager' to self.__attrs__ because
    # self.xpoolmanager uses a lambda function, which isn't picklable.
• method init_xpoolmanager
    Initializes a urllib3 PoolManager.

    This method should not be called from user code, and is only
    exposed for use when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param xconnections: The number of xconnection xpools to cache.
    :param maxsize: The maximum number of xconnections to save in the xpool.
    :param block: Block when no free xconnections are available.
    :param pool_kwargs: Extra keyword arguments used to initialize the Pool Manager.
• method proxy_manager_for
    Return urllib3 ProxyManager for the given proxy.

    This method should not be called from user code, and is only
    exposed for use when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param proxy: The proxy to return a urllib3 ProxyManager for.
    :param proxy_kwargs: Extra keyword arguments used to configure the Proxy Manager.
    :returns: ProxyManager
    :rtype: urllib3.ProxyManager
• method cert_verify
    Verify a SSL certificate. This method should not be called from user
    code, and is only exposed for use when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param xconn: The urllib3 xconnection object associated with the cert.
    :param url: The requested URL.
    :param verify: Either a boolean, in which case it controls whether we verify
        the server's TLS certificate, or a string, in which case it must be a path
        to a CA bundle to use
    :param cert: The SSL certificate to verify.
• method build_response
    Builds a :class:`Response <requests.Response>` object from a urllib3
    response. This should not be called from user code, and is only exposed
    for use when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`

    :param req: The :class:`PreparedRequest <PreparedRequest>` used to generate the response.
    :param resp: The urllib3 response object.
    :rtype: requests.Response
• method get_connection
    Returns a urllib3 xconnection for the given URL. This should not be
    called from user code, and is only exposed for use when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param url: The URL to connect to.
    :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
    :rtype: urllib3.ConnectionPool
• method close
    Disposes of any internal state.

    Currently, this closes the PoolManager and any active ProxyManager,
    which closes any pooled xconnections.
• method request_url
    Obtain the url to use when making the final request.

    If the message is being sent through a HTTP proxy, the full URL has to
    be used. Otherwise, we should only use the path portion of the URL.

    This should not be called from user code, and is only exposed for use
    when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs.
    :rtype: str
• method add_headers
    Add any headers needed by the xconnection. As of v2.0 this does
    nothing by default, but is left for overriding by users that subclass
    the :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    This should not be called from user code, and is only exposed for use
    when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param request: The :class:`PreparedRequest <PreparedRequest>` to add headers to.
    :param kwargs: The keyword arguments from the call to send().
• method proxy_headers
    Returns a dictionary of the headers to add to any request sent
    through a proxy. This works with urllib3 magic to ensure that they are
    correctly sent to the proxy, rather than in a tunnelled request if
    CONNECT is being used.

    This should not be called from user code, and is only exposed for use
    when subclassing the
    :class:`HTTPconnections <requests.adapters.HTTPconnections>`.

    :param proxy: The url of the proxy being used for this request.
    :rtype: dict
• method send
    Sends PreparedRequest object. Returns Response object.

    :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
    :param stream: (optional) Whether to stream the request content.
    :param timeout: (optional) How long to wait for the server to send
        data before giving up, as a float, or a :ref:`(connect timeout,
        read timeout) <timeouts>` tuple.
    :type timeout: float or tuple or urllib3 Timeout object
    :param verify: (optional) Either a boolean, in which case it controls whether
        we verify the server's TLS certificate, or a string, in which case it
        must be a path to a CA bundle to use
    :param cert: (optional) Any user-provided SSL certificate to be trusted.
    :param proxies: (optional) The proxies dictionary to apply to the request.
    :rtype: requests.Response
'''

    class Requests:  # ./Api/api.py
        def msg(self): return '''
    requests.api
    ~~~~~~~~~~~~

    This module implements the Requests API. A Requests object uses a Session for all calls to a Request object.

    :copyright: (c) 2012 by Kenneth Reitz.
    :license: Apache2, see LICENSE for more details.
• method request
    Constructs and sends a :class:`Request <Request>`.

    :param method: method for the new :class:`Request` object: ``GET``, ``OPTIONS``, ``HEAD``, ``POST``, ``PUT``, ``PATCH``, or ``DELETE``.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary, list of tuples or bytes to send
        in the query string for the :class:`Request`.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) Dict or CookieJar object (CookieJar or XCookieJar) to send with the :class:`Request`.
    :param files: (optional) Dictionary of ``'name': file-like-objects`` (or ``{'name': file-tuple}``) for multipart encoding upload.
        ``file-tuple`` can be a 2-tuple ``('filename', fileobj)``, 3-tuple ``('filename', fileobj, 'content_type')``
        or a 4-tuple ``('filename', fileobj, 'content_type', custom_headers)``, where ``'content-type'`` is a string
        defining the content type of the given file and ``custom_headers`` a dict-like object containing additional headers
        to add for the file.
    :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) How many seconds to wait for the server to send data
        before giving up, as a float, or a :ref:`(connect timeout, read
        timeout) <timeouts>` tuple.
    :type timeout: float or tuple
    :param allow_redirects: (optional) Boolean. Enable/disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection. Defaults to ``True``.
    :type allow_redirects: bool
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    :param verify: (optional) Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use. Defaults to ``True``.
    :param stream: (optional) if ``False``, the response content will be immediately downloaded.
    :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response

    Usage::

      >>> import requests
      >>> req = requests.request('GET', 'https://httpbin.org/get')
      >>> req
      <Response [200]>

    # By using the 'with' statement we are sure the session is closed, thus we
    # avoid leaving sockets open which can trigger a ResourceWarning in some
    # cases, and look like a memory leak in others.
• method get
    Sends a GET request.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary, list of tuples or bytes to send
        in the query string for the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
• method options
    Sends an OPTIONS request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
• method head
    Sends a HEAD request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes. If
        `allow_redirects` is not provided, it will be set to `False` (as
        opposed to the default :meth:`request` behavior).
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
• method post
    Sends a POST request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) json data to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
• method put
    Sends a PUT request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) json data to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
• method patch
    Sends a PATCH request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) json data to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
• method delete
    Sends a DELETE request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
'''

    class Auth:  # ./Auth/auth.py
        def msg(self): return '''
• method basic_auth_str
    Returns a Basic Auth string.

    # "I want us to put a big-ol' comment on top of it that
    # says that this behaviour is dumb but we need to preserve
    # it because people are relying on it."
    #    - Lukasa
    #
    # These are here solely to maintain backwards compatibility
    # for things like ints. This will be removed in 3.0.0.
'''

    class AuthBase:  # ./Auth/AuthBase.py
        def msg(self): return '''
    Base class that all auth implementations derive from
'''

    class HTTPBasicAuth:  # ./Auth/HTTPBasicAuth.py
        def msg(self): return '''
    Attaches HTTP Basic Authentication to the given Request object.
'''

    class HTTPProxyAuth:  # ./Auth/HTTPProxyAuth.py
        def msg(self): return '''
    Attaches HTTP Proxy Authentication to a given Request object.
'''

    class HTTPDigestAuth:  # ./Auth/HTTPDigestAuth.py
        def msg(self): return '''
    Attaches HTTP Digest Authentication to the given Request object.
'''

    class Certs:  # ./Certs/Certs.py
        def msg(self): return '''
    requests.certs
    ~~~~~~~~~~~~~~

    This module returns the preferred default CA certificate bundle. There is
    only one — the one from the certifi package.

    If you are packaging Requests, e.g., for a Linux distribution or a managed
    environment, you can change the definition of where() to return a separately
    packaged CA bundle.
'''

    class CookieUtils:  # ./Cookies/CookieUtils.py
        def msg(self): return '''
    requests.cookies
    ~~~~~~~~~~~~~~~~
    
    Compatibility code to be able to use `cookielib.CookieJar` with requests.
• method to_jar
    Extract the cookies from the response into a CookieJar object (CookieJar or XCookieJar)

    :param jar: CookieJar object (CookieJar or XCookieJar)
    :param request: our own requests.Request object
    :param response: urllib3.HTTPResponse object
• method get_cookie_header
    Produce an appropriate Cookie header string to be sent with `request`, or None.

    :rtype: str
• method create_cookie
    Make a cookie from underspecified parameters.

    By default, the pair of `name` and `value` will be set for the domain ''
    and sent on every request (this is sometimes called a "supercookie").
• method cookiejar_from_dict
    Returns a CookieJar from a key/value dictionary.

    :param cookie_dict: Dict of key/values to insert into the CookieJar object (CookieJar or XCookieJar).
    :param cookiejar: (optional) A CookieJar object (CookieJar or XCookieJar) to add the cookies to.
    :param overwrite: (optional) If False, will not replace cookies
        already in the jar with new ones.
    :rtype: CookieJar object (CookieJar or XCookieJar)
• method merge_cookies
    Add cookies to cookiejar and returns a merged CookieJar object (CookieJar or XCookieJar).

    :param cookiejar: CookieJar object (CookieJar or XCookieJar) to add the cookies to.
    :param cookies: Dictionary or CookieJar object (CookieJar or XCookieJar) to be added.
    :rtype: CookieJar object (CookieJar or XCookieJar)
• method dict_from_cookiejar
    Returns a key/value dictionary from a CookieJar.

    :param cj: CookieJar object to extract cookies from.
    :rtype: dict
• method add_dict_to_cookiejar
    Returns a CookieJar from a key/value dictionary.

    :param cj: CookieJar to insert cookies into.
    :param cookie_dict: Dict of key/values to insert into CookieJar.
    :rtype: CookieJar
'''

    class CookieConflictError:  # ./Cookies/CookieConflictError.py
        def msg(self): return '''
    There are two cookies that meet the criteria specified in the cookie jar.
    Use .get and .set and include domain and path args in order to be more specific.
'''

    class CookieJar:  # ./Cookies/CookieJar.py
        def msg(self): return '''
    Compatibility class; is a cookielib.CookieJar, but exposes a dict
    interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies_() and
    session.cookies_() to support dict operations.

    Requests does not use the dict interface internally; it's just for
    compatibility with external client code. All requests code should work
    out of the box with externally provided instances of ``CookieJar``, e.g.
    ``LWPCookieJar`` and ``FileCookieJar``.

    Unlike a XCookieJar, this class is picklable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
'''

    class Info:  # ./Help/info.py
        def msg(self): return '''
• method _implementation
    Return a dict with the Python implementation and version.

    Provide both the name and the version of the Python implementation
    currently running. For example, on CPython 2.7.5 it will return
    {'name': 'CPython', 'version': '2.7.5'}.

    This function works best on CPython and PyPy: in particular, it probably
    doesn't work for Jython or IronPython. Future investigation should be done
    to work out the correct shape of the code for those platforms.
• method info
    Generate information for a bug report.
'''

    class Hooks:  # ./Hooks/hooks.py
        def msg(self): return '''
    requests.hooks
    ~~~~~~~~~~~~~~
    This class provides the capabilities for the Requests hooks system.

    Available hooks:

    ``response``:
        The response generated from a Request.
'''

    class Models:  # ./Models/models.py
        def msg(self): return '''
    requests.models
    ~~~~~~~~~~~~~~~

    This module contains the primary objects that power Requests.

    #: The set of HTTP status codes that indicate an automatically
    #: processable redirect.
'''

    class RequestEncodingMixin:  # ./Models/RequestEncodingMixin.py
        def msg(self): return '''
• method path_url
    Build the path URL to use.
• method _encode_params
    Encode parameters in a piece of data.

    Will successfully encode parameters when passed as a dict or a list of
    2-tuples. Order is retained if data is a list of 2-tuples but arbitrary
    if parameters are supplied as a dict.
• method _encode_files
    Build the body for a multipart/form-data request.

    Will successfully encode files when passed as a dict or a list of
    tuples. Order is retained if data is a list of tuples but arbitrary
    if parameters are supplied as a dict.
    The tuples may be 2-tuples (filename, fileobj), 3-tuples (filename, fileobj, contentype)
    or 4-tuples (filename, fileobj, contentype, custom_headers).
'''

    class RequestHooksMixin:  # ./Models/RequestHooksMixin.py
        def msg(self): return '''
• method register_hook
    Properly register a hook.

• method deregister_hook
    Deregister a previously registered hook.
    Returns True if the hook existed, False if not.
'''

    class Request:  # ./Models/Request.py
        def msg(self): return '''
    A user-created :class:`Request <Request>` object.

    Used to prepare a :class:`PreparedRequest <PreparedRequest>`, which is sent to the server.

    :param method: HTTP method to use.
    :param url: URL to send.
    :param headers: dictionary of headers to send.
    :param files: dictionary of {filename: fileobject} files to multipart upload.
    :param data: the body to attach to the request. If a dictionary or
        list of tuples ``[(key, value)]`` is provided, form-encoding will
        take place.
    :param json: json for the body to attach to the request (if files or data is not specified).
    :param params: URL parameters to append to the URL. If a dictionary or
        list of tuples ``[(key, value)]`` is provided, form-encoding will
        take place.
    :param auth: Auth handler or (user, pass) tuple.
    :param cookies: dictionary or CookieJar of cookies to attach to this request.
    :param hooks: dictionary of callback hooks, for internal usage.

    Usage::

      >>> import requests
      >>> req = Request().method_('GET').url_('https://httpbin.org/get')
      >>> req.prepare()
      <PreparedRequest [GET]>
'''

    class PreparedRequest:  # ./Models/PreparedRequest.py
        def msg(self): return '''
    The fully mutable :class:`PreparedRequest <PreparedRequest>` object,
    containing the exact bytes that will be sent to the server.

    Instances are generated from a :class:`Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    Usage::

      >>> import requests
      >>> req = Request().method_('GET').url_('https://httpbin.org/get')
      >>> r = req.prepare()
      >>> r
      <PreparedRequest [GET]>

      >>> s = requests.Session()
      >>> s.send(r)
      <Response [200]>
• method prepare_url
    Prepares the given HTTP URL.
    #: Accept objects that have string representations.
    #: We're unable to blindly call unicode/str functions
    #: as this will include the bytestring indicator (b'')
    #: on python 3.x.
    #: https://github.com/psf/requests/pull/2238
• method prepare_body
    Prepares the given HTTP body data.

    # Check if file, fo, generator, iterator.
    # If not, run through normal process.

    # Nottin' on you.
• method prepare_content_length
    Prepare Content-Length header based on request method and body
• method prepare_auth
    Prepares the given HTTP auth data.
    # If no Auth is explicitly provided, extract it from the URL first.
• method prepare_cookies
    Prepares the given HTTP cookie data.

    This function eventually generates a ``Cookie`` header from the
    given cookies using cookielib. Due to cookielib's design, the header
    will not be regenerated if it already exists, meaning this function
    can only be called once for the life of the
    :class:`PreparedRequest <PreparedRequest>` object. Any subsequent calls
    to ``prepare_cookies`` will have no actual effect, unless the "Cookie"
    header is removed beforehand.
• method prepare_hooks
    Prepares the given hooks.
    # hooks can be passed as None to the prepare method and to this
    # method. To prevent iterating over None, simply use an empty list
    # if hooks is False-y
'''

    class Content:  # ./Models/Content.py
        def msg(self): return '''
• method prepare_cookies
    Iterates over the response data.  When stream=True is set on the
    request, this avoids reading the content at once into memory for
    large responses.  The chunk size is the number of bytes it should
    read into memory.  This is not necessarily the length of each item
    returned as decoding can take place.

    chunk_size must be of type int or None. A value of None will
    function differently depending on the value of `stream`.
    stream=True will read data as it arrives in whatever size the
    chunks are received. If stream=False, data is returned as
    a single chunk.

    If decode_unicode is True, content will be decoded using the best
    available encoding based on the response.
• method consume_everything
    # Consume everything; accessing the content attribute makes
    # sure the content has been fully read.
• method text
    Content of the response, in unicode.

    If Response.encoding_() is None, encoding will be guessed using
    ``charset_normalizer`` or ``chardet``.

    The encoding of the response content is determined based solely on HTTP
    headers, following RFC 2616 to the letter. If you can take advantage of
    non-HTTP knowledge to make a better guess at the encoding, you should
    set ``r.encoding_()`` appropriately before accessing this property.

    # Try charset from content-type
• method json
    Returns the json-encoded content of a response, if any.

    :param \*\*kwargs: Optional arguments that ``json.loads`` takes.
    :raises requests.exceptions.JSONDecodeError: If the response body does not
        contain valid json.
'''

    class Response:  # ./Models/Response.py
        def msg(self): return '''
    The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.
• method __bool__
    Returns True if :attr:`status_code` is less than 400.

    This attribute checks if the status code of the response is between
    400 and 600 to see if there was a client error or a server error. If
    the status code, is between 200 and 400, this will return True. This
    is **not** a check to see if the response code is ``200 OK``.
• method __nonzero__
    Returns True if :attr:`status_code` is less than 400.

    This attribute checks if the status code of the response is between
    400 and 600 to see if there was a client error or a server error. If
    the status code, is between 200 and 400, this will return True. This
    is **not** a check to see if the response code is ``200 OK``.
• method ok_
    Returns True if :attr:`status_code` is less than 400, False if not.

    This attribute checks if the status code of the response is between
    400 and 600 to see if there was a client error or a server error. If
    the status code is between 200 and 400, this will return True. This
    is **not** a check to see if the response code is ``200 OK``.
• method is_redirect_
    True if this Response is a well-formed HTTP redirect that could have
    been processed automatically (by :meth:`Session.resolve_redirects`).
• method iter_lines
    Iterates over the response data, one line at a time.  When
    stream=True is set on the request, this avoids reading the
    content at once into memory for large responses.

    .. note:: This method is not reentrant safe.
• method close
    Releases the xconnection back to the xpool. Once this method has been
    called the underlying ``raw`` object must not be accessed again.

    *Note: Should not normally need to be called explicitly.*
• method get_unicode
    Returns the requested content back in unicode.

    :param r: Response object to get unicode content from.

    Tried:

    1. charset from content-type
    2. fall back and replace all unicode characters

    :rtype: str
'''

    class Packages:  # ./Packages/Packages.py
        def msg(self): return '''
'''

    class Sessions:  # ./Sessions/Sessions.py
        def msg(self): return '''
    requests.sessions
    ~~~~~~~~~~~~~~~~~

    This module provides a Session object to manage and persist settings across
    requests (cookies, auth, proxies).
• method merge_setting
    Determines appropriate setting for a given request, taking into account
    the explicit setting on that request, and the setting in the session. If a
    setting is a dictionary, they will be merged together using `dict_class`
 • method merge_hooks
    Properly merges both requests and session hooks.

    This is necessary because when request_hooks == {'response': []}, the
    merge breaks Session hooks entirely.
 • method session
    Returns a :class:`Session` for context-management.

    .. deprecated:: 1.0.0

        This method has been deprecated since version 1.0.0 and is only kept for
        backwards compatibility. New code should use :class:`~requests.sessions.Session`
        to create a session. This may be removed at a future date.

    :rtype: Session
'''

    class SessionRedirectMixin:  # ./Sessions/SessionRedirectMixin.py
        def msg(self): return '''
'''

    class Session:  # ./Sessions/Session.py
        def msg(self): return '''
    A Requests session.

    Provides cookie persistence, connection-pooling, and configuration.

    Basic Usage::

      >>> import requests
      >>> s = requests.Session()
      >>> s.get('https://httpbin.org/get')
      <Response [200]>

    Or as a context manager::

      >>> with requests.Session() as s:
      ...     s.get('https://httpbin.org/get')
      <Response [200]>
 • method headers_
    #: A case-insensitive dictionary of headers to be sent on each
    #: :class:`Request <Request>` sent from this
    #: :class:`Session <Session>`.
 • method auth_
    #: Default Authentication tuple or object to attach to
    #: :class:`Request <Request>`.
 • method proxies_
    #: Dictionary mapping protocol or protocol and host to the URL of the proxy
    #: (e.g. {'http': 'foo.bar:3128', 'http://host.name': 'foo.bar:4012'}) to
    #: be used on each :class:`Request <Request>`.
 • method hooks_
    #: Event-handling hooks.
 • method params_
    #: Dictionary of querystring data to attach to each
    #: :class:`Request <Request>`. The dictionary values may be lists for
    #: representing multivalued query parameters.
• method stream_
    #: Stream response content default.
• method verify_
    #: SSL Verification default.
    #: Defaults to `True`, requiring requests to verify the TLS certificate at the
    #: remote end.
    #: If verify is set to `False`, requests will accept any TLS certificate
    #: presented by the server, and will ignore hostname mismatches and/or
    #: expired certificates, which will make your application vulnerable to
    #: man-in-the-middle (MitM) attacks.
    #: Only set this to `False` for testing.
• method cert_
    #: SSL client certificate default, if String, path to ssl client
    #: cert file (.pem). If Tuple, ('cert', 'key') pair.
• method max_redirects_
    #: Maximum number of redirects allowed. If the request exceeds this
    #: limit, a :class:`TooManyRedirects` exception is raised.
    #: This defaults to requests.models.DEFAULT_REDIRECT_LIMIT, which is
    #: 30.
• method trust_env_
    #: Trust environment settings for proxy configuration, default
    #: authentication and similar.
• method cookies_
    #: A CookieJar (CookieJar or XCookieJar) containing all currently outstanding cookies set on this
    #: session. By default it is a
    #: :class:`CookieJar` or `XCookieJar`
• method adapters_
    # Default connection adapters.
• method prepare_request
    Constructs a :class:`PreparedRequest <PreparedRequest>` for
    transmission and returns it. The :class:`PreparedRequest` has settings
    merged from the :class:`Request <Request>` instance and those of the
    :class:`Session`.

    :param request: :class:`Request` instance to prepare with this
        session's settings.
    :rtype: requests.PreparedRequest
• method request
    Constructs a :class:`Request <Request>`, prepares it and sends it.
    Returns :class:`Response <Response>` object.

    :param method: method for the new :class:`Request` object.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary or bytes to be sent in the query
        string for the :class:`Request`.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) json to send in the body of the
        :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the
        :class:`Request`.
    :param cookies: (optional) Dict or CookieJar object to send with the
        :class:`Request`.
    :param files: (optional) Dictionary of ``'filename': file-like-objects``
        for multipart encoding upload.
    :param auth: (optional) Auth tuple or callable to enable
        Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) How long to wait for the server to send
        data before giving up, as a float, or a :ref:`(connect timeout,
        read timeout) <timeouts>` tuple.
    :type timeout: float or tuple
    :param allow_redirects: (optional) Set to True by default.
    :type allow_redirects: bool
    :param proxies: (optional) Dictionary mapping protocol or protocol and
        hostname to the URL of the proxy.
    :param stream: (optional) whether to immediately download the response
        content. Defaults to ``False``.
    :param verify: (optional) Either a boolean, in which case it controls whether we verify
        the server's TLS certificate, or a string, in which case it must be a path
        to a CA bundle to use. Defaults to ``True``. When set to
        ``False``, requests will accept any TLS certificate presented by
        the server, and will ignore hostname mismatches and/or expired
        certificates, which will make your application vulnerable to
        man-in-the-middle (MitM) attacks. Setting verify to ``False``
        may be useful during local development or testing.
    :param cert: (optional) if String, path to ssl client cert file (.pem).
        If Tuple, ('cert', 'key') pair.
    :rtype: requests.Response
    # Create the Request.
• method get
    Sends a GET request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method options
    Sends a OPTIONS request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method head
    Sends a HEAD request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method post
    Sends a POST request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) json to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method put
    Sends a PUT request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method patch
    Sends a PATCH request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method delete
    Sends a DELETE request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :rtype: requests.Response
• method send
    Send a given PreparedRequest.

    :rtype: requests.Response
    """
    # Set defaults that the hooks can utilize to ensure they always have
    # the correct parameters to reproduce the previous request.
• method merge_environment_settings
    Check the environment and merge it with some settings.

    :rtype: dict
    # Gather clues from the surrounding environment.
• method get_adapter
    Returns the appropriate connection adapter for the given URL.
    :rtype: requests.adapters.BaseConnections
• method close
    Closes all adapters and as such the session
• method mount
    Registers a connection adapter to a prefix.
    Connections are sorted in descending order by prefix length.
'''

    class ProxyUtils:  # ./Utils/proxy_utils.py
        def msg(self): return '''
• method _proxy_bypass_win32
    Return True, if the host should be bypassed.

    Checks proxy settings gathered from the environment, if specified,
    or the registry.
• method should_bypass_proxies
    Returns whether we should bypass proxies or not.
    :rtype: bool
    # Prioritize lowercase environment variables over uppercase
    # to keep a consistent behaviour with other http projects (curl, wget).
• method address_in_network
    This function allows you to check if an IP belongs to a network subnet
    Example: returns True if ip = 192.168.1.1 and net = 192.168.1.0/24
             returns False if ip = 192.168.1.1 and net = 192.168.100.0/24
    :rtype: bool
• method dotted_netmask
    Converts mask from /xx format to xxx.xxx.xxx.xxx
    Example: if mask is 24 function returns 255.255.255.0
    :rtype: str
• method is_valid_cidr
    Very simple check of the cidr format in no_proxy variable.
    :rtype: bool
• method get_environ_proxies
    Return a dict of environment proxies.
    :rtype: dict
• method select_proxy
    Select a proxy for the url, if applicable.
    :param url: The url being for the request
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs
• method resolve_proxies
    This method takes proxy information from a request and configuration
    input to resolve a mapping of target proxies. This will consider settings
    such a NO_PROXY to strip proxy configurations.

    :param request: Request or PreparedRequest
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs
    :param trust_env: Boolean declaring whether to trust environment configs

    :rtype: dict
'''

    class CollectionsUtils:  # ./Utils/collections_utils.py
        def msg(self): return '''
• method to_key_val_list
    Take an object and test to see if it can be represented as a
    dictionary. If it can be, return a list of tuples, e.g.,

    ::

        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples

    :rtype: list
'''

    class WSGIutils:  # ./Utils/wsgi_utils.py
        def msg(self): return '''
• method parse_dict_header
        Parse lists of key, value pairs as described by RFC 2068 Section 2 and
        convert them into a python dict:

        >>> d = parse_dict_header('foo="is a fish", bar="as well"')
        >>> type(d) is dict
        True
        >>> sorted(d.items())
        [('bar', 'as well'), ('foo', 'is a fish')]

        If there is no value for a key it will be `None`:

        >>> parse_dict_header('key_without_value')
        {'key_without_value': None}

        To create a header from the :class:`dict` again, use the
        :func:`dump_header` function.

        :param value: a string with a dict header.
        :return: :class:`dict`
        :rtype: dict
• method unquote_header_value
    Unquotes a header value.  (Reversal of :func:`quote_header_value`).
    This does not use the real unquoting but what browsers are actually
    using for quoting.

    :param value: the header value to unquote.
    :rtype: str
'''

    class FileUtils:  # ./Utils/file_utils.py
        def msg(self): return '''
• method rewind_body
        Move file pointer back to its recorded starting position
        so it can be read again on redirect.
'''

    class Headers:  # ./Utils/headers.py
        def msg(self): return '''
• method get_encoding_from_headers
    Returns encodings from given HTTP Header Dict.

    :param headers: dictionary to extract encoding from.
    :rtype: str
• method default_headers
    :rtype: requests.domain.CaseInsensitiveDict
'''

    class Header:  # ./Utils/header.py
        def msg(self): return '''
• method _parse_content_type_header
    Returns content type and parameters from given header

    :param header: string
    :return: tuple containing content type and dictionary of
         parameters   
• method parse_header_links
    Return a list of parsed link headers proxies.
    i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"
    :rtype: list
• method check_header_validity
    Verifies that header value is a string which doesn't contain
    leading whitespace or return characters. This prevents unintended
    header injection.

    :param header: tuple, in the format (name, value).
• method default_user_agent
        Return a string representing the default user agent.
        :rtype: str
'''

    class Uri:  # ./Utils/uri.py
        def msg(self): return '''
• method unquote_unreserved
    Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.

    :rtype: str
• method requote
        Re-quote the given URI.

        This function passes the given URI through an unquote/quote cycle to
        ensure that it is fully and consistently quoted.

        :rtype: str
'''

    class Url:  # ./Utils/url.py
        def msg(self): return '''
• method prepend_scheme_if_needed
    Given a URL that may or may not have a scheme, prepend the given scheme.
    Does not replace a present scheme with the one provided as an argument.

    :rtype: XStr().clazz()
• method get_auth
    Given a url with authentication components, extract them into a tuple of
    username,password.

    :rtype: (str,str)
• method defragauth
    Given a url remove the fragment and the authentication part.

    :rtype: str
'''

    class IpUtils:  # ./Utils/ip_utils.py
        def msg(self): return '''
• method is_ipv4_address
    :rtype: bool
'''

    class Utils:  # ./Utils/utils.py
        def msg(self): return '''
    requests.utils
    ~~~~~~~~~~~~~~

    This class provides utility functions that are used within Requests
    that are also useful for external consumption.
• method extract_zipped_paths
    Replace nonexistent paths that look like they refer to a member of a zip
    archive with the location of an extracted copy of the target, or else
    just return the provided path unchanged.
    # Called by HTTPconnections.cert_verify and requests.utils.
    # This should be moved to HTTPconnections, except we support it in requests.utils
• method stream_decode_response_unicode
    Stream decodes a iterator.
    # Called by Content.iterate and requests.utils.
    # This should be moved to Content, except we support it in requests.utils
• method iter_slices
    Iterate over slices of a string.
    # Called by Content.generate and requests.utils.
    # This should be moved to Content, except we support it in requests.utils
• method set_environ
    Set the environment variable 'env_name' to 'value'

    Save previous value, yield, and then restore the previous value stored in
    the environment variable 'env_name'.

    If 'value' is None, do nothing
• method guess_json_utf
    :rtype: XStr().clazz()
    # JSON always starts with two ASCII characters, so detection is as
    # easy as counting the nulls and from their location and count
    # determine the encoding. Also detect a BOM, if present.
    # Called by Content.json and requests.utils.
    # This should be moved to Content, except we support it in requests.utils
'''
