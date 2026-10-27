import ssl
from unittest.mock import Mock

import requests.adapters


def test_request_url_handles_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "//v:h" == a.request_url(p, {})


def _https_request():
    request = Mock()
    request.url = "https://example.com/"
    request.headers = {}
    return request


def test_custom_sslcontext_preserves_verify_mode():
    """A custom SSLContext is not forced to CERT_REQUIRED by the pool key."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    adapter = requests.adapters.HTTPAdapter()
    adapter.init_poolmanager(1, 1, ssl_context=ctx)

    _host_params, pool_kwargs = requests.adapters._urllib3_request_context(
        _https_request(), True, None, adapter.poolmanager
    )

    assert "cert_reqs" not in pool_kwargs


def test_default_verify_enforces_cert_required():
    """verify=True with no custom context still requires certificates."""
    adapter = requests.adapters.HTTPAdapter()
    adapter.init_poolmanager(1, 1)

    _host_params, pool_kwargs = requests.adapters._urllib3_request_context(
        _https_request(), True, None, adapter.poolmanager
    )

    assert pool_kwargs.get("cert_reqs") == "CERT_REQUIRED"
