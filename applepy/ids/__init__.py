"""Module for managing Apple's Identity Services (IDS) credential paths."""
from typing import Final

IDS_ROOT: Final = resources.files(__package__)

CREDENTIALS_DIR: Final = IDS_ROOT / "credentials"

AUTH_KEY_PATH: Final = CREDENTIALS_DIR / "auth.key"
AUTH_CERT_PATH: Final = CREDENTIALS_DIR / "auth.crt"
AUTH_CSR_PATH: Final = CREDENTIALS_DIR / "auth.csr"
PUSH_KEY_PATH: Final = CREDENTIALS_DIR / "push.key"
PUSH_CERT_PATH: Final = CREDENTIALS_DIR / "push.crt"
ENCRYPTION_KEY_PATH: Final = CREDENTIALS_DIR / "encryption.key"
ENCRYPTION_PUBLIC_KEY_PATH: Final = CREDENTIALS_DIR / "encryption.pub"
SIGNING_KEY_PATH: Final = CREDENTIALS_DIR / "signing.key"
SIGNING_PUBLIC_KEY_PATH: Final = CREDENTIALS_DIR / "signing.pub"
REGISTRATION_CERT_PATH: Final = CREDENTIALS_DIR / "registration.crt"
IDS_DOTENV: Final = CREDENTIALS_DIR / ".env"
PROTOCOL_VERSION: Final = "1640"
