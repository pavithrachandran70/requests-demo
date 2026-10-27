import errno
import os
import tempfile

import pytest

import requests.adapters


class _Conn:
    """Stand-in urllib3 connection. cert_verify only assigns attributes on it."""


def test_request_url_handles_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "//v:h" == a.request_url(p, {})


def test_missing_cert_raises_file_not_found_error():
    """AC1: Missing cert path raises FileNotFoundError with filename attribute."""
    adapter = requests.adapters.HTTPAdapter()
    missing_cert_path = "/tmp/does-not-exist-adlc-cert.pem"
    conn = _Conn()

    with pytest.raises(FileNotFoundError) as exc_info:
        adapter.cert_verify(conn, "https://example.com", True, missing_cert_path)

    exc = exc_info.value
    assert isinstance(exc, FileNotFoundError)
    assert isinstance(exc, OSError)
    assert exc.errno == errno.ENOENT
    assert exc.filename == missing_cert_path
    assert "TLS certificate file" in str(exc)


def test_missing_key_raises_file_not_found_error():
    """AC2: Missing key path raises FileNotFoundError with filename attribute."""
    adapter = requests.adapters.HTTPAdapter()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False
    ) as cert_file:
        cert_file.write("dummy cert content")
        valid_cert_path = cert_file.name

    missing_key_path = "/tmp/does-not-exist-adlc-key.pem"
    conn = _Conn()

    try:
        with pytest.raises(FileNotFoundError) as exc_info:
            adapter.cert_verify(
                conn, "https://example.com", True, (valid_cert_path, missing_key_path)
            )

        exc = exc_info.value
        assert isinstance(exc, FileNotFoundError)
        assert isinstance(exc, OSError)
        assert exc.errno == errno.ENOENT
        assert exc.filename == missing_key_path
        assert "TLS certificate key file" in str(exc)
    finally:
        os.unlink(valid_cert_path)


def test_file_not_found_error_is_caught_by_oserror():
    """AC1/AC2: Confirm FileNotFoundError is caught by except OSError."""
    adapter = requests.adapters.HTTPAdapter()
    missing_path = "/tmp/does-not-exist.pem"
    conn = _Conn()

    caught_as_oserror = False
    try:
        adapter.cert_verify(conn, "https://example.com", True, missing_path)
    except OSError:
        caught_as_oserror = True
    except Exception:
        pass

    assert caught_as_oserror, "FileNotFoundError should be caught by except OSError"
