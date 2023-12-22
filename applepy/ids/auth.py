"""Module containing functions for authenticating with Apple's servers."""
import plistlib
from base64 import b64decode
from functools import partial
from logging import getLogger
from os import getenv
from typing import Final, Literal

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
from rich.pretty import pretty_repr

from applepy.bags import ids_bag
from applepy.crypto_helper import (
    create_private_key,
    randbytes,
    read_certificate,
    read_private_key,
    save_certificate,
    strip_pem,
)
from applepy.ids import AUTH_CERT_PATH, AUTH_KEY_PATH, IDS_DOTENV, PROTOCOL_VERSION
from applepy.ids.payload import generate_auth_headers
from applepy.status_codes import StatusCode

AUTHENTICATE_USER_KEY: Final = "vc-profile-authenticate"
AUTHENTICATE_USER_URL: Final = ids_bag[AUTHENTICATE_USER_KEY]

AUTHENTICATE_DEVICE_KEY: Final = "id-authenticate-ds-id"
AUTHENTICATE_DEVICE_URL: Final = ids_bag[AUTHENTICATE_DEVICE_KEY]

GET_HANDLES_KEY: Final = "id-get-handles"
GET_HANDLES_URL: Final = ids_bag[GET_HANDLES_KEY]

ALLOWED_AUTH_ATTEMPTS: Final = 3

load_dotenv(IDS_DOTENV)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = getLogger(__name__)


class IDSAuthenticationResponseError(Exception):
    """Exception raised when an IDS authentication request returns an error."""

    def __init__(self: "IDSAuthenticationResponseError", location: str, status_code: StatusCode) -> None:
        """
        Initialize an IDSAuthenticationResponseError.

        :param location: The location of the request.
        :param status_code: The status code returned by the request.
        """
        self.status_code = status_code
        super().__init__(f"IDS authentication error in {location}: {status_code}")


def auth_user(
    username: str = "",
    password: str = "",
    code: str = "",
    force: bool = False,
    _tries: int = 1,
) -> tuple[str, str]:
    """
    Authenticate the user's credentials with IDS.

    :param username: The user's Apple ID.
    :param password: The user's Apple ID password.
    :param code: The 2FA code sent to the user's device.
    :param force: Whether to force re-authentication, ignoring cached credentials.
    :param _tries: The number of times this function has been called. Do not pass this argument.
    :return: A tuple containing the user's profile ID and authentication token.
    """
    profile_id = getenv("PROFILE_ID")
    if AUTH_KEY_PATH.is_file() and AUTH_CERT_PATH.is_file() and profile_id and not force:
        logger.info("Already device authenticated with IDS. Skipping user authentication...")
        return profile_id, ""

    if force:
        logger.info("Forcing re-authentication for user.")

    reauth_user = partial(auth_user, _tries=_tries + 1)

    if _tries > ALLOWED_AUTH_ATTEMPTS:
        raise Exception("Too many failed authentication attempts.")

    if not username or not password:
        logger.debug("Asking user for Apple ID credentials.")

    # TODO: Move input to main() and pass it to auth_user().
    username = username or input("Apple ID: ").strip()
    password = f"{password}{code}" or pwinput("Password: ").strip()

    data = {
        "username": username,
        "password": password,
    }

    logger.debug(f"Sending user auth request to {ids_bag[AUTHENTICATE_USER_KEY]}.")

    response = requests.post(
        AUTHENTICATE_USER_URL,
        data=plistlib.dumps(data),
        verify=False,  # noqa: S501
        timeout=10,
    )
    auth_payload = plistlib.loads(response.content)

    match status_code := StatusCode(auth_payload.get("status")):
        case StatusCode.SUCCESS:
            logger.info("Apple ID successfully authenticated.")

        case StatusCode.UNAUTHENTICATED:
            logger.debug("Sending user a 2FA code.")
            logger.info("A 2FA code has been sent to your device. Press ENTER for a new code.")
            code = input("Enter 2FA code: ").strip()
            if not code:
                logger.debug("User requested a new 2FA code.")
                return reauth_user(username, password, tries=_tries - 1)
            return reauth_user(username, password, code=code)

        case StatusCode.ACTION_AUTHENTICATION_FAILED:
            if code:
                logger.error("Invalid 2FA code. Please try again.")
                return reauth_user(username, password)

            logger.error("Invalid username or password. Please try again.")
            return reauth_user()

        case _:
            raise IDSAuthenticationResponseError(AUTHENTICATE_USER_KEY, status_code)

    logger.debug(f"Response Payload: {pretty_repr(auth_payload)}")

    profile_id = auth_payload["profile-id"]
    auth_token = auth_payload["auth-token"]

    set_key(IDS_DOTENV, "PROFILE_ID", profile_id)
    set_key(IDS_DOTENV, "AUTH_TOKEN", auth_token)

    return profile_id, auth_token


def auth_device(profile_id: str, auth_token: str) -> tuple[RSAPrivateKey, Certificate]:
    """Authenticate with Apple's servers to obtain an authentication certificate."""
    # Check if we already have a private key and certificate.
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

    logger.debug(f"Sending device auth request to {AUTHENTICATE_DEVICE_URL} via v{PROTOCOL_VERSION}.")
    logger.debug(f"Request payload: {pretty_repr(data)}")

    response = requests.post(
        AUTHENTICATE_DEVICE_URL,
        headers={
            "x-protocol-version": PROTOCOL_VERSION,
        },
        data=payload,
        verify=False,  # noqa: S501
        timeout=10,
    )

    payload = plistlib.loads(response.content)
    status_code = StatusCode(payload.get("status"))
    if status_code != StatusCode.SUCCESS:
        raise IDSAuthenticationResponseError(AUTHENTICATE_DEVICE_KEY, status_code)

    certificate = load_der_x509_certificate(payload["cert"])
    save_certificate(AUTH_CERT_PATH, certificate)

    logger.info("Successfully obtained authentication certificate from IDS.")
    logger.debug(f"Certificate valid until {certificate.not_valid_after.astimezone()}.")

    return private_key, certificate


def get_handles(  # noqa: PLR0913 - TODO: Refactor
    profile_id: str,
    push_key: RSAPrivateKey,
    push_cert: Certificate,
    auth_key: RSAPrivateKey,
    auth_cert: Certificate,
    push_token: bytes,
) -> list[dict[Literal["uri"], str]]:
    """
    Retrieve the user's handles.

    :param profile_id: The user's profile ID.
    :param push_key: The user's push private key.
    :param push_cert: The user's push certificate.
    :param auth_key: The user's authentication private key.
    :param auth_cert: The user's authentication certificate.
    :param push_token: The user's push token.
    :return: A list of the user's handles.
    """
    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id": profile_id,
        **generate_auth_headers(push_key, push_cert, auth_key, auth_cert, GET_HANDLES_KEY, push_token),
    }

    logger.debug(f"Sending request to {GET_HANDLES_URL} via v{PROTOCOL_VERSION}.")
    logger.debug(f"Headers: {pretty_repr(headers)}")

    response = requests.get(
        GET_HANDLES_URL,
        headers=headers,
        verify=False,  # noqa: S501
        timeout=10,
    )

    payload = plistlib.loads(response.content)

    logger.debug(f"Response payload: {pretty_repr(payload)}")

    status_code = StatusCode(payload.get("status"))
    match status_code:
        case StatusCode.SUCCESS:
            ...

        case _:
            raise IDSAuthenticationResponseError(GET_HANDLES_KEY, status_code)

    handles = payload["handles"]

    handles_simple = [handle["uri"] for handle in handles]
    logger.info(f"Obtained the following handles: {handles_simple}")

    return handles
