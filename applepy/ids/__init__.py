"""Module for managing Apple's Identity Services (IDS) credential paths."""
from typing import Final

from applepy.data_dirs import USER_DATA_DIR

CREDENTIALS_DIR: Final = USER_DATA_DIR / "IDS Credentials"

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

CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
IDS_DOTENV.touch(exist_ok=True)
