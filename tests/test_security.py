import ipaddress

import pytest
from pydantic import ValidationError

from graylog_mcp.config import Settings
from graylog_mcp.security import LoginThrottle, SecretCipher, SessionStore, ip_allowed, resolve_client_ip


def test_session_store_is_bounded_expires_and_validates_csrf():
    store = SessionStore(ttl_seconds=60, max_sessions=2)
    first_token, first = store.create(now=100)
    second_token, second = store.create(now=101)
    third_token, third = store.create(now=102)

    assert store.get(first_token, now=102) is None
    assert store.get(second_token, now=102) == second
    assert store.get(third_token, now=102) == third
    assert store.get(second_token, now=162) is None

    live_store = SessionStore(ttl_seconds=60, max_sessions=2)
    live_token, live_session = live_store.create()
    assert live_store.valid_csrf(live_token, live_session.csrf_token)
    assert not live_store.valid_csrf(live_token, "wrong")


def test_login_throttle_uses_a_sliding_window():
    throttle = LoginThrottle(max_attempts=2, window_seconds=60)
    assert throttle.allowed("192.0.2.1", now=100)
    throttle.register_failure("192.0.2.1", now=100)
    throttle.register_failure("192.0.2.1", now=110)
    assert not throttle.allowed("192.0.2.1", now=120)
    assert throttle.allowed("192.0.2.1", now=171)


def test_login_throttle_has_a_bounded_client_store():
    throttle = LoginThrottle(max_attempts=2, window_seconds=60, max_clients=2)
    throttle.register_failure("192.0.2.1", now=100)
    throttle.register_failure("192.0.2.2", now=100)
    throttle.register_failure("192.0.2.3", now=100)
    assert len(throttle) == 2
    assert throttle.allowed("192.0.2.1", now=100)


def test_forwarded_ip_is_only_used_for_trusted_immediate_proxy():
    trusted = (ipaddress.ip_network("172.16.0.0/12"),)
    assert resolve_client_ip("203.0.113.4", "198.51.100.8", trusted) == "203.0.113.4"
    assert resolve_client_ip("172.20.0.5", "198.51.100.8, 172.20.0.4", trusted) == "198.51.100.8"
    assert resolve_client_ip("172.20.0.5", "192.0.2.99, 198.51.100.8", trusted) == "198.51.100.8"
    assert ip_allowed("198.51.100.8", ["198.51.100.0/24"])
    assert not ip_allowed("203.0.113.8", ["198.51.100.0/24"])
    assert not ip_allowed("not-an-ip", ["198.51.100.0/24"])


def test_secret_cipher_roundtrip_and_plaintext_compatibility():
    cipher = SecretCipher("stable-test-master-key-32-characters")
    encrypted = cipher.encrypt("graylog-token")
    assert encrypted.startswith("enc:v1:")
    assert encrypted != "graylog-token"
    assert cipher.decrypt(encrypted) == "graylog-token"
    assert cipher.decrypt("legacy-plaintext") == "legacy-plaintext"


def test_settings_rejects_a_weak_encryption_key():
    with pytest.raises(ValidationError):
        Settings(ui_password="a-strong-test-password", secret_encryption_key="too-short")
