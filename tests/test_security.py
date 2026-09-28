"""安全基元测试：密码哈希、HMAC 令牌签名与篡改识别。"""

from __future__ import annotations

import pytest

from authapp.errors import TokenInvalid
from authapp.security import (
    b64url_decode,
    b64url_encode,
    decode_token,
    encode_token,
    hash_password,
    verify_password,
)

SECRET = "unit-secret"


def test_password_hash_roundtrip():
    h = hash_password("s3cret!")
    assert h != "s3cret!"
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret!", h)
    assert not verify_password("wrong", h)


def test_password_hash_uses_random_salt():
    assert hash_password("same") != hash_password("same")


def test_verify_password_handles_garbage():
    assert not verify_password("x", "not-a-valid-hash")
    assert not verify_password("x", "other$1$aa$bb")


def test_b64url_roundtrip():
    raw = bytes(range(256))
    encoded = b64url_encode(raw)
    assert "=" not in encoded
    assert b64url_decode(encoded) == raw


def test_token_roundtrip():
    claims = {"sub": "u1", "jti": "t1", "iat": 1.0, "exp": 2.0}
    token = encode_token(claims, SECRET)
    assert decode_token(token, SECRET) == claims


def test_tampered_payload_detected():
    token = encode_token({"sub": "u1"}, SECRET)
    header, payload, signature = token.split(".")
    # 翻转载荷内容但保留原签名 -> 必须识别为篡改
    tampered_payload = b64url_encode(b'{"sub":"u2"}')
    tampered = f"{header}.{tampered_payload}.{signature}"
    with pytest.raises(TokenInvalid) as exc:
        decode_token(tampered, SECRET)
    assert exc.value.code == "token_invalid"


def test_signature_with_other_secret_fails():
    token = encode_token({"sub": "u1"}, SECRET)
    with pytest.raises(TokenInvalid):
        decode_token(token, "another-secret")


@pytest.mark.parametrize(
    "bad_token",
    [
        "not-a-token",
        "a.b",
        "a.b.c.d",
        "aaa.bbb.ccc",  # base64 解码失败
        "",
    ],
)
def test_malformed_token(bad_token):
    with pytest.raises(TokenInvalid):
        decode_token(bad_token, SECRET)
