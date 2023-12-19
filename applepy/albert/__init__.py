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

from applepy.crypto_helper import (
    create_private_key,
    read_certificate,
    read_csr,
    read_private_key,
    save_certificate,
    save_csr,
)

ALBERT_ROOT: Final = resources.files(__package__)

CRYPTO_ASSETS_DIR: Final = ALBERT_ROOT / "crypto_assets"

FAIRPLAY_PRIVATE_KEY: Final = read_private_key(CRYPTO_ASSETS_DIR / "fairplay.key")
FAIRPLAY_CERT_CHAIN: Final = (CRYPTO_ASSETS_DIR / "fairplay-chain.crt").read_bytes()
DEVICE_KEY_PATH: Final = CRYPTO_ASSETS_DIR / "device.key"
DEVICE_CSR_PATH: Final = CRYPTO_ASSETS_DIR / "device.csr"
DEVICE_CERTIFICATE_PATH: Final = CRYPTO_ASSETS_DIR / "device.crt"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if not FAIRPLAY_PRIVATE_KEY:
    raise FileNotFoundError("FairPlay private key not found!")

if not FAIRPLAY_CERT_CHAIN:
    raise FileNotFoundError("FairPlay certificate chain not found!")


def _generate_device_csr(private_key: RSAPrivateKey) -> CertificateSigningRequest:
    csr = CertificateSigningRequestBuilder(
        subject_name=x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Cupertino"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
                x509.NameAttribute(NameOID.COMMON_NAME, str(uuid4())),
            ],
        ),
    ).sign(private_key, SHA256())

    save_csr(DEVICE_CSR_PATH, csr)

    return csr


UID: Final = str(uuid4())
ACTIVATION_URL: Final = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS"
PRIVATE_KEY: Final = read_private_key(DEVICE_KEY_PATH) or create_private_key(DEVICE_KEY_PATH)
CSR: Final = read_csr(DEVICE_CSR_PATH) or _generate_device_csr(PRIVATE_KEY)
# noinspection SpellCheckingInspection
ACTIVATION_INFO_PAYLOAD: Final = {
    "ActivationRandomness": str(uuid4()),
    "ActivationState": "Unactivated",
    "BuildVersion": "23C64",
    "DeviceCertRequest": CSR.public_bytes(Encoding.PEM),
    "DeviceClass": "MacOS",
    "ProductType": "MacBookAir8,1",
    "ProductVersion": "14.2",
    "SerialNumber": "CYT1YMJK7N",
    "UniqueDeviceID": UID,
}

logger = getLogger(__name__)


class AlbertException(Exception):
    ...


def request_push_cert() -> tuple[RSAPrivateKey, Certificate]:
    if (private_key := read_private_key(DEVICE_KEY_PATH)) and (
        certificate := read_certificate(DEVICE_CERTIFICATE_PATH)
    ):
        return private_key, certificate

    activation_plist = plistlib.dumps(ACTIVATION_INFO_PAYLOAD)
    activation_signature = FAIRPLAY_PRIVATE_KEY.sign(activation_plist, PKCS1v15(), SHA1())

    payload = {
        "ActivationInfoComplete": True,
        "ActivationInfoXML": activation_plist,
        "FairPlayCertChain": FAIRPLAY_CERT_CHAIN,
        "FairPlaySignature": activation_signature,
    }

    logger.info(f"Requesting push certificate from {ACTIVATION_URL}.")
    logger.debug(f"Request payload: {payload}")

    response = requests.post(
        ACTIVATION_URL,
        data={"activation-info": plistlib.dumps(payload)},
    )

    if (match := re.search(r"<Protocol>(.*)</Protocol>", response.text)) is None:
        raise AlbertException("Certificate missing from Albert response!")

    protocol_data = plistlib.loads(match.group(1).encode())

    device_certificate = load_pem_x509_certificate(
        protocol_data["device-activation"]["activation-record"]["DeviceCertificate"],
    )
    save_certificate(DEVICE_CERTIFICATE_PATH, device_certificate)

    logger.info("Successfully received push certificate from Albert.")

    return PRIVATE_KEY, device_certificate
