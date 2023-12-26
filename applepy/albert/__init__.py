"""
Module for interacting with Albert.

Albert is a service provided by Apple that allows devices to request push certificates.
This module contains functions for requesting a push certificate from Albert.
"""
import plistlib
import re
from importlib import resources
from logging import getLogger
from typing import Final
from uuid import uuid4

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Certificate,
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import NameOID
from rich.pretty import pretty_repr

from applepy.crypto_helper import (
    create_private_key,
    read_certificate,
    read_csr,
    read_private_key,
    save_certificate,
    save_csr,
)
from applepy.data_dirs import USER_DATA_DIR

RESOURCES_ROOT = resources.files(__package__)

LOCAL_FAIRPLAY_PRIVATE_KEY_PATH: Final = RESOURCES_ROOT / "fairplay.key"
LOCAL_FAIRPLAY_CERT_CHAIN_PATH: Final = RESOURCES_ROOT / "fairplay-chain.crt"

CRYPTO_ASSETS_DIR: Final = USER_DATA_DIR / "Albert Credentials"
CRYPTO_ASSETS_DIR.mkdir(parents=True, exist_ok=True)

FAIRPLAY_PRIVATE_KEY_PATH: Final = CRYPTO_ASSETS_DIR / "fairplay.key"
FAIRPLAY_CERT_CHAIN_PATH: Final = CRYPTO_ASSETS_DIR / "fairplay-chain.crt"
PUSH_KEY_PATH: Final = CRYPTO_ASSETS_DIR / "push.key"
PUSH_CSR_PATH: Final = CRYPTO_ASSETS_DIR / "push.csr"
PUSH_CERTIFICATE_PATH: Final = CRYPTO_ASSETS_DIR / "push.crt"

UID: Final = str(uuid4())

logger = getLogger(__name__)

if not FAIRPLAY_PRIVATE_KEY_PATH.is_file():
    logger.info("FairPlay private key not found in user data directory, copying from resources.")
    logger.debug(f"FairPlay private key path: {FAIRPLAY_PRIVATE_KEY_PATH}")

    with FAIRPLAY_PRIVATE_KEY_PATH.open("wb") as f:
        f.write(LOCAL_FAIRPLAY_PRIVATE_KEY_PATH.read_bytes())

if not FAIRPLAY_CERT_CHAIN_PATH.is_file():
    logger.info("FairPlay certificate chain not found in user data directory, copying from resources.")
    logger.debug(f"FairPlay certificate chain path: {FAIRPLAY_CERT_CHAIN_PATH}")

    with FAIRPLAY_CERT_CHAIN_PATH.open("wb") as f:
        f.write(LOCAL_FAIRPLAY_CERT_CHAIN_PATH.read_bytes())

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not FAIRPLAY_PRIVATE_KEY_PATH.is_file():
    raise FileNotFoundError("FairPlay private key not found!")

if not FAIRPLAY_CERT_CHAIN_PATH.is_file():
    raise FileNotFoundError("FairPlay certificate chain not found!")


def _generate_device_csr(private_key: RSAPrivateKey) -> CertificateSigningRequest:
    """Generate a `CertificateSigningRequest` used for the request to Albert."""
    csr = CertificateSigningRequestBuilder(
        subject_name=x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Cupertino"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
                x509.NameAttribute(NameOID.COMMON_NAME, UID),
            ],
        ),
    ).sign(private_key, SHA256())

    save_csr(PUSH_CSR_PATH, csr)

    return csr


ACTIVATION_URL: Final = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"
PRIVATE_KEY: Final = read_private_key(PUSH_KEY_PATH) or create_private_key(PUSH_KEY_PATH)
CSR: Final = read_csr(PUSH_CSR_PATH) or _generate_device_csr(PRIVATE_KEY)
# noinspection SpellCheckingInspection
ACTIVATION_INFO_PAYLOAD: Final = {
    "ActivationRandomness": str(uuid4()),
    "ActivationState": "Unactivated",
    "DeviceCertRequest": CSR.public_bytes(Encoding.PEM),
    "DeviceClass": "MacOS",
    "ProductType": "Macmini7,1",
    "ProductVersion": "12.7.2",
    "BuildVersion": "21G1974",
    "SerialNumber": "C02WP16GJ1GJ",
    "UniqueDeviceID": UID,
}

logger = getLogger(__name__)


class AlbertError(Exception):
    """Semantic base exception for Albert-related errors."""


def request_push_cert() -> tuple[RSAPrivateKey, Certificate]:
    """
    Request a push certificate from Albert.

    :return: A `tuple` containing the private key and the push certificate.
    """
    if (private_key := read_private_key(PUSH_KEY_PATH)) and (certificate := read_certificate(PUSH_CERTIFICATE_PATH)):
        return private_key, certificate

    activation_plist = plistlib.dumps(ACTIVATION_INFO_PAYLOAD)
    private_key = read_private_key(FAIRPLAY_PRIVATE_KEY_PATH) or create_private_key(FAIRPLAY_PRIVATE_KEY_PATH)
    activation_signature = private_key.sign(activation_plist, PKCS1v15(), SHA1())  # noqa: S303

    payload = {
        "ActivationInfoComplete": True,
        "ActivationInfoXML": activation_plist,
        "FairPlayCertChain": FAIRPLAY_CERT_CHAIN_PATH.read_bytes(),
        "FairPlaySignature": activation_signature,
    }

    logger.info("Requesting push certificate from Albert.")
    logger.debug(f"Sending request to {ACTIVATION_URL}.")
    logger.debug(f"Request payload: {pretty_repr(payload)}")

    response = requests.post(
        ACTIVATION_URL,
        data={"activation-info": plistlib.dumps(payload)},
        timeout=10,
    )

    if (match := re.search(r"<Protocol>(.*)</Protocol>", response.text)) is None:
        raise AlbertError("Certificate missing from Albert response!")

    protocol_data = plistlib.loads(match.group(1).encode())

    device_certificate = load_pem_x509_certificate(
        protocol_data["device-activation"]["activation-record"]["DeviceCertificate"],
    )
    save_certificate(PUSH_CERTIFICATE_PATH, device_certificate)

    logger.info("Successfully received push certificate from Albert.")

    return PRIVATE_KEY, device_certificate
