"""Parse a pypush-style config.json file and import the credentials into the correct locations."""
import json
from importlib.abc import Traversable

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from dotenv import set_key

from applepy.albert import PUSH_CERTIFICATE_PATH, PUSH_KEY_PATH
from applepy.apns import APNS_DOTENV
from applepy.crypto_helper import save_certificate, save_private_key
from applepy.ids import (
    AUTH_CERT_PATH,
    AUTH_KEY_PATH,
    ENCRYPTION_KEY_PATH,
    IDS_DOTENV,
    REGISTRATION_CERT_PATH,
    SIGNING_KEY_PATH,
)


def import_credentials(path: Traversable) -> None:
    """Import credentials from a pypush-style config.json file."""
    if not path.is_file():
        return

    with path.open("r") as f:
        config = json.load(f)

    save_private_key(PUSH_KEY_PATH, load_pem_private_key(config["push"]["key"].encode(), password=None))
    save_certificate(PUSH_CERTIFICATE_PATH, load_pem_x509_certificate(config["push"]["cert"].encode()))

    save_private_key(AUTH_KEY_PATH, load_pem_private_key(config["auth"]["key"].encode(), password=None))
    save_certificate(AUTH_CERT_PATH, load_pem_x509_certificate(config["auth"]["cert"].encode()))

    save_certificate(REGISTRATION_CERT_PATH, load_pem_x509_certificate(config["id"]["cert"].encode()))

    save_private_key(SIGNING_KEY_PATH, load_pem_private_key(config["encryption"]["ec_key"].encode(), password=None))
    save_private_key(ENCRYPTION_KEY_PATH, load_pem_private_key(config["encryption"]["rsa_key"].encode(), password=None))

    set_key(APNS_DOTENV, "PUSH_TOKEN", config["push"]["token"])
    set_key(IDS_DOTENV, "PROFILE_ID", config["auth"]["user_id"])
