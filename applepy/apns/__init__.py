"""Module for the Apple Push Notification Service (APNs)."""
from applepy.data_dirs import USER_DATA_DIR

APNS_DOTENV = USER_DATA_DIR / "APNs.env"

APNS_DOTENV.touch(exist_ok=True)
