import plistlib
from base64 import b64decode
from functools import partial
from logging import getLogger
from os import getenv
from random import randbytes
from typing import Literal

import requests
import urllib3
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Certificate,
    CertificateSigningRequestBuilder,
    Name,
    NameAttribute,
    NameOID,
    load_der_x509_certificate,
)
from dotenv import load_dotenv, set_key
from pwinput import pwinput

from applepy.bags import ids_bag
from applepy.crypto_helper import create_private_key, read_certificate, read_private_key, save_certificate, strip_pem
from applepy.ids import AUTH_CERT_PATH, AUTH_KEY_PATH, IDS_DOTENV, PROTOCOL_VERSION
from applepy.ids.payload import generate_auth_headers
from applepy.status_codes import StatusCode

AUTHENTICATE_USER_KEY = "vc-profile-authenticate"
AUTHENTICATE_USER_URL = ids_bag[AUTHENTICATE_USER_KEY]

AUTHENTICATE_DEVICE_KEY = "id-authenticate-ds-id"
AUTHENTICATE_DEVICE_URL = ids_bag[AUTHENTICATE_DEVICE_KEY]

GET_HANDLES_KEY = "id-get-handles"
GET_HANDLES_URL = ids_bag[GET_HANDLES_KEY]

load_dotenv(IDS_DOTENV)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = getLogger(__name__)


class IDSAuthenticationResponseError(Exception):
    def __init__(self, location: str, status_code: StatusCode) -> None:
        self.status_code = status_code
        super().__init__(f"IDS authentication error in {location}: {status_code}")


def auth_user(
    username: str = "",
    password: str = "",
    code: str = "",
    tries: int = 0,
    force: bool = False,
) -> tuple[str, str]:
    profile_id = getenv("PROFILE_ID")
    auth_token = getenv("AUTH_TOKEN")
    if profile_id and auth_token and not force:
        logger.info("Using existing Apple ID credentials.")
        return profile_id, auth_token

    if force:
        logger.info("Forcing re-authentication for user.")

    reauth_user = partial(auth_user, tries=tries + 1)

    if tries > 3:
        raise Exception("Too many failed authentication attempts.")

    if not username or not password:
        logger.debug("Asking user for Apple ID credentials.")
        print("Please enter your Apple ID credentials.")

    username = username or input("Username: ").strip()
    password = f"{password}{code}" or pwinput("Password: ").strip()

    data = {
        "username": username,
        "password": password,
    }

    response = requests.post(
        ids_bag[AUTHENTICATE_USER_KEY],
        data=plistlib.dumps(data),
        verify=False,
    )
    auth_payload = plistlib.loads(response.content)

    match status_code := StatusCode(auth_payload.get("status")):
        case StatusCode.SUCCESS:
            logger.info("Apple ID successfully authenticated.")

        case StatusCode.UNAUTHENTICATED:
            logger.debug("Sending user a 2FA code.")
            print("A 2FA code has been sent to your device. Press ENTER for a new code.")
            code = input("Enter 2FA code: ").strip()
            if code == "":
                logger.debug("User requested a new 2FA code.")
                return reauth_user(username, password, tries=tries - 1)
            return reauth_user(username, password, code=code)

        case StatusCode.ACTION_AUTHENTICATION_FAILED:
            if code:
                logger.error("Invalid 2FA code. Please try again.")
                return reauth_user(username, password)
            else:
                logger.error("Invalid username or password. Please try again.")
                return reauth_user()

        case _:
            raise IDSAuthenticationResponseError(AUTHENTICATE_USER_KEY, status_code)

    profile_id = auth_payload["profile-id"]
    auth_token = auth_payload["auth-token"]

    set_key(IDS_DOTENV, "PROFILE_ID", profile_id)
    set_key(IDS_DOTENV, "AUTH_TOKEN", auth_token)

    return profile_id, auth_token


def auth_device(profile_id: str, auth_token: str) -> tuple[RSAPrivateKey, Certificate]:
    if (private_key := read_private_key(AUTH_KEY_PATH)) and (auth_cert := read_certificate(AUTH_CERT_PATH)):
        return private_key, auth_cert

    private_key = create_private_key(AUTH_KEY_PATH)

    csr = (
        CertificateSigningRequestBuilder(
            subject_name=Name(
                [
                    NameAttribute(NameOID.COMMON_NAME, randbytes(20).hex()),
                ],
            ),
        )
        .sign(private_key, SHA256())
        .public_bytes(Encoding.PEM)
        .decode()
    )

    data = {
        "authentication-data": {"auth-token": auth_token},
        "csr": b64decode(strip_pem(csr)),
        "realm-user-id": profile_id,
    }

    payload = plistlib.dumps(data)

    logger.debug(f"Sending request to {ids_bag[AUTHENTICATE_DEVICE_KEY]} via v{PROTOCOL_VERSION}.")
    logger.debug(f"{payload = }")

    response = requests.post(
        AUTHENTICATE_DEVICE_URL,
        headers={
            "x-protocol-version": PROTOCOL_VERSION,
        },
        data=payload,
        verify=False,
    )

    payload = plistlib.loads(response.content)
    status_code = StatusCode(payload.get("status"))
    if status_code != StatusCode.SUCCESS:
        raise IDSAuthenticationResponseError(AUTHENTICATE_DEVICE_KEY, status_code)

    logger.info(f"Obtained certificate from {AUTHENTICATE_DEVICE_KEY}.")

    certificate = load_der_x509_certificate(payload["cert"])
    save_certificate(AUTH_CERT_PATH, certificate)

    logger.debug(f"Certificate valid until {certificate.not_valid_after.astimezone()}.")

    return private_key, certificate


def get_handles(
    profile_id: str,
    push_key: RSAPrivateKey,
    push_cert: Certificate,
    auth_key: RSAPrivateKey,
    auth_cert: Certificate,
    push_token: bytes,
) -> list[dict[Literal["uri"], str]]:
    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id": profile_id,
        **generate_auth_headers(push_key, push_cert, auth_key, auth_cert, GET_HANDLES_KEY, push_token),
    }

    logger.debug(f"Sending request to {ids_bag[GET_HANDLES_KEY]} via v{PROTOCOL_VERSION}.")
    logger.debug(f"{headers = }")

    response = requests.get(GET_HANDLES_URL, headers=headers, verify=False)
    payload = plistlib.loads(response.content)

    status_code = StatusCode(payload.get("status"))
    match status_code:
        case StatusCode.SUCCESS:
            ...

        case _:
            raise IDSAuthenticationResponseError(GET_HANDLES_KEY, status_code)

    handles = payload["handles"]

    handles_simple = [handle["uri"] for handle in handles]
    logger.info(f"Obtained handles from {GET_HANDLES_URL}: {handles_simple}")

    return handles
