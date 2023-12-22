"""Registration with Apple's Identity Services."""
import plistlib
from base64 import b64decode
from logging import getLogger
from string import ascii_lowercase
from typing import Final, Literal
from uuid import UUID

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, load_der_x509_certificate
from rich.pretty import pretty_repr

from applepy.albert import ACTIVATION_INFO_PAYLOAD
from applepy.bags import ids_bag
from applepy.crypto_helper import (
    choices,
    create_private_key,
    create_public_key,
    read_certificate,
    read_private_key,
    read_public_key,
    save_certificate,
)
from applepy.ids import (
    ENCRYPTION_KEY_PATH,
    ENCRYPTION_PUBLIC_KEY_PATH,
    PROTOCOL_VERSION,
    REGISTRATION_CERT_PATH,
    SIGNING_KEY_PATH,
    SIGNING_PUBLIC_KEY_PATH,
)
from applepy.ids.auth import IDSAuthenticationResponseError
from applepy.ids.payload import generate_auth_headers
from applepy.status_codes import StatusCode

REGISTER_KEY: Final = "id-register"
REGISTER_URL: Final[str] = ids_bag[REGISTER_KEY]

VALIDATION_URL: Final = "https://validation-data.fly.dev/generate"

logger = getLogger(__name__)


def _create_identity_key() -> bytes:
    encryption_key = read_private_key(ENCRYPTION_KEY_PATH) or create_private_key(ENCRYPTION_KEY_PATH, key_size=1280)
    encryption_public_key = read_public_key(ENCRYPTION_PUBLIC_KEY_PATH) or create_public_key(
        ENCRYPTION_PUBLIC_KEY_PATH,
        encryption_key,
    )

    signing_key: ec.EllipticCurvePrivateKey = create_private_key(SIGNING_KEY_PATH, ec.EllipticCurvePrivateKey)
    signing_public_key: ec.EllipticCurvePublicKey = read_public_key(
        SIGNING_PUBLIC_KEY_PATH,
        ec.EllipticCurvePublicKey,
    ) or create_public_key(SIGNING_PUBLIC_KEY_PATH, signing_key)

    result = b""
    result += b"\x30\x81\xF6\x81\x43\x00\x41\x04"
    result += signing_public_key.public_numbers().x.to_bytes(32, "big")
    result += signing_public_key.public_numbers().y.to_bytes(32, "big")
    result += b"\x82\x81\xAE"

    # Raw RSA certificate
    result += b"\x00\xAC\x30\x81\xA9\x02\x81\xA1"
    result += encryption_public_key.public_numbers().n.to_bytes(161, "big")
    result += b"\x02\x03\x01\x00\x01"

    return result


# noinspection SpellCheckingInspection
def register(  # noqa: PLR0913 - TODO: Refactor
    profile_id: str,
    push_key: RSAPrivateKey,
    push_cert: Certificate,
    auth_key: RSAPrivateKey,
    auth_cert: Certificate,
    push_token: bytes,
    handles: list[dict[Literal["uri"], str]],
) -> Certificate:
    """Attempt to register a device with Apple's Identity Services."""
    if registration_certificate := read_certificate(REGISTRATION_CERT_PATH):
        logger.info("Using existing registration certificate.")
        return registration_certificate

    logger.info("Requesting validation data...")

    validation_response = requests.get(
        VALIDATION_URL,
        timeout=(5, 30),  # This API seems to be remarkably slow
    )

    validation_data = validation_response.content.decode()

    logger.info("Received validation data.")

    operating_system = "Mac OS X" if ACTIVATION_INFO_PAYLOAD["DeviceClass"] == "MacOS" else "iOS"
    build_version = "19H2026"
    os_version = f"{operating_system},10.15.7,{build_version}"
    product_type = ACTIVATION_INFO_PAYLOAD["ProductType"]

    data = {
        "language": "en-US",
        "device-name": f"{''.join(choices(ascii_lowercase, k=12))}'s Mac",
        "hardware-version": product_type,
        "os-version": os_version,
        "software-version": build_version,
        "private-device-data": {
            "u": UUID(ACTIVATION_INFO_PAYLOAD["UniqueDeviceID"]).hex.upper(),
        },
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "sub-services": [
                    "com.apple.private.alloy.sms",
                    "com.apple.private.alloy.gelato",
                    "com.apple.private.alloy.biz",
                    "com.apple.private.alloy.gamecenter.imessage",
                ],
                "users": [
                    {
                        "client-data": {
                            "is-c2k-equipment": True,
                            "optionally-receive-typing-indicators": True,
                            "public-message-identity-key": _create_identity_key(),
                            "public-message-identity-version": 2,
                            "show-peer-errors": True,
                            "supports-ack-v1": True,
                            "supports-activity-sharing-v1": True,
                            "supports-audio-messaging-v2": True,
                            "supports-autoloopvideo-v1": True,
                            "supports-be-v1": True,
                            "supports-ca-v1": True,
                            "supports-fsm-v1": True,
                            "supports-fsm-v2": True,
                            "supports-fsm-v3": True,
                            "supports-ii-v1": True,
                            "supports-impact-v1": True,
                            "supports-inline-attachments": True,
                            "supports-keep-receipts": True,
                            "supports-location-sharing": True,
                            "supports-media-v2": True,
                            "supports-photos-extension-v1": True,
                            "supports-st-v1": True,
                            "supports-update-attachments-v1": True,
                        },
                        "uris": handles,
                        "user-id": profile_id,
                    },
                ],
            },
        ],
        "validation-data": b64decode(validation_data),
    }

    payload = plistlib.dumps(data)

    headers = {
        "User-Agent": f"com.apple.invitation-registration [Mac OS X,{os_version},{build_version},{product_type}]",
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id-0": profile_id,
        **generate_auth_headers(push_key, push_cert, auth_key, auth_cert, REGISTER_KEY, push_token, 0, payload=payload),
    }

    logger.debug(f"Sending request to {REGISTER_URL} via v{PROTOCOL_VERSION}.")
    logger.debug(f"Headers: {pretty_repr(headers)}")
    logger.debug(f"Payload (pre-plist): {pretty_repr(data)}")

    response = requests.post(
        REGISTER_URL,
        headers=headers,
        data=payload,
        verify=False,  # noqa: S501
        timeout=10,
    )

    response_data = plistlib.loads(response.content)
    logger.debug(f"Response payload: {pretty_repr(response_data)}")

    status_code = StatusCode(response_data["status"])
    match status_code:
        case StatusCode.SUCCESS:
            ...

        case StatusCode.ACTION_RETRY_WITH_NEW_ABSINTHE_CONTEXT:
            logger.error("IDS registration has rejected the validation data.")
            raise IDSAuthenticationResponseError(REGISTER_KEY, status_code)

        case _:
            raise IDSAuthenticationResponseError(REGISTER_KEY, status_code)

    try:
        certificate_response = response_data["services"][0]["users"][0]["cert"]

    except KeyError as e:
        logger.error("Certificate not included in response!")
        raise IDSAuthenticationResponseError(REGISTER_KEY, StatusCode.UNKNOWN) from e

    logger.info("Successfully registered.")

    registration_certificate = load_der_x509_certificate(certificate_response)

    save_certificate(REGISTRATION_CERT_PATH, registration_certificate)

    return registration_certificate
