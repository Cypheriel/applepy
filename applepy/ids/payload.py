"""Payload generation for IDS requests."""
from base64 import b64encode
from datetime import datetime
from random import randbytes

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import Certificate

from applepy.crypto_helper import strip_pem


def to_length_value(data: bytes, length: int = 4):
    """Prepend the length of the data to the data."""
    return len(data).to_bytes(length, "big") + data


def _generate_payload(
    bag_key: str | None = None,
    query_string: str | None = None,
    payload: bytes | None = None,
    push_token: bytes | None = None,
):
    """Generate a nonce and payload."""
    bag_key = bag_key or ""
    query_string = query_string or ""
    payload = payload or b""
    push_token = push_token or b""

    nonce = b"\x01" + int(datetime.now().timestamp() * 1_000).to_bytes(8, "big") + randbytes(8)

    return (
        b64encode(nonce),
        nonce
        + to_length_value(bag_key.encode())
        + to_length_value(query_string.encode())
        + to_length_value(payload)
        + to_length_value(push_token),
    )


def generate_signed_payload(
    private_key: RSAPrivateKey,
    bag_key: str | None = None,
    query_string: str | None = None,
    payload: bytes | None = None,
    push_token: bytes | None = None,
):
    """Generate a signed payload."""
    nonce, payload = _generate_payload(bag_key, query_string, payload, push_token)
    signed_payload = b64encode(b"\x01\x01" + private_key.sign(payload, PKCS1v15(), SHA1()))
    return nonce, signed_payload


def generate_auth_headers(
    push_key: RSAPrivateKey,
    push_cert: Certificate,
    auth_key: RSAPrivateKey,
    auth_cert: Certificate,
    bag_key: str,
    push_token: bytes,
    auth_suffix_number: int | None = None,
    payload: bytes | None = None,
):
    """Generate authentication headers."""
    push_nonce, push_sig = generate_signed_payload(
        private_key=push_key,
        bag_key=bag_key,
        payload=payload,
        push_token=push_token,
    )
    auth_nonce, auth_sig = generate_signed_payload(
        private_key=auth_key,
        bag_key=bag_key,
        payload=payload,
        push_token=push_token,
    )
    auth_suffix = f"-{auth_suffix_number}" if auth_suffix_number is not None else ""
    return {
        "x-push-sig": push_sig,
        "x-push-nonce": push_nonce,
        "x-push-cert": strip_pem(push_cert),
        "x-push-token": b64encode(push_token),
        f"x-auth-sig{auth_suffix}": auth_sig,
        f"x-auth-nonce{auth_suffix}": auth_nonce,
        f"x-auth-cert{auth_suffix}": strip_pem(auth_cert),
    }


def generate_id_headers(
    auth_key: RSAPrivateKey,
    registration_cert: Certificate,
    bag_key: str,
    push_token: bytes,
    payload: bytes | None = None,
):
    """Generate identification headers for some IDS requests."""
    nonce, sig = generate_signed_payload(
        private_key=auth_key,
        bag_key=bag_key,
        payload=payload,
        push_token=push_token,
    )
    return {
        "x-id-sig": sig,
        "x-id-nonce": nonce,
        "x-id-cert": strip_pem(registration_cert),
        "x-push-token": b64encode(push_token),
    }
