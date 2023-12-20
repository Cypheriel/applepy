"""Entry point for the application script."""
import os
import sys
from logging import getLogger
from typing import Callable

from rich.prompt import Confirm

from applepy.albert import request_push_cert
from applepy.apns.manager import APNSManager
from applepy.bags import apns_bag, ids_bag
from applepy.ids.auth import auth_device, auth_user, get_handles
from applepy.ids.registration import register
from applepy.init_logging import setup_logging, log_file, upload_log, file_handler

setup_logging()
logger = getLogger("applepy")
apns = APNSManager()


def entrypoint(func: Callable[..., int]) -> None:
    logger.info(f"Writing log to temporary file: {log_file.name}")
    """General boilerplate for entrypoint functions such as `main()`."""

    try:
        exit_code = func() or 0

    except KeyboardInterrupt:
        exit_code = 127

    except Exception as e:
        logger.error("Unhandled exception: ", exc_info=e)
        exit_code = 1

    if Confirm.ask("Upload log file?") or os.getenv("UPLOAD_LOG") == "1":
        logger.warning("Log file may contain sensitive information. Please be cautious about who you share this with!")
        url = upload_log()
        print(f"Uploaded log: {url}")

    apns.courier_stream.close()

    logger.info(f"Removing temporary log file: {log_file.name}")

    file_handler.close()
    log_file.close()
    os.remove(log_file.name)

    sys.exit(exit_code)


@entrypoint
def main(*_args: str, **_kwargs: str) -> int:
    """Entry point function this package."""
    # Obtain the APNs and IDS bags which contain varying endpoints used by various Apple services.
    logger.debug(f"APNs bag: {apns_bag}")
    logger.debug(f"IDS bag: {ids_bag}")

    # Obtain the private key that signed the CSR and the resulting push certificate from Apple.
    push_key, push_cert = request_push_cert()

    # Send a CONNECT packet to APNs.
    apns.connect(push_key, push_cert)

    # Filter the APNs connection to only receive notifications for the Madrid topic.
    apns.filter_topics(["com.apple.madrid"])

    # Authenticate with the user's Apple ID, obtaining their profile ID and authentication token.
    profile_id, auth_token = auth_user()

    # Authenticate with Apple's servers to obtain a private key used to sign another CSR and the resulting certificate.
    auth_key, auth_cert = auth_device(profile_id, auth_token)

    # Register the user's available handles tied to their Apple ID.
    handles = get_handles(profile_id, push_key, push_cert, auth_key, auth_cert, apns.push_token)

    # Complete device registration using most collected credentials.
    registration_cert = register(profile_id, push_key, push_cert, auth_key, auth_cert, apns.push_token, handles)
    results = apns.query(handles[0]["uri"], [input("Handle: ")], auth_key, registration_cert)
    logger.info(f"Received response from APNs query: {results}")

    # Query the identities tied to a handle of the user's choice (or the own user if "self" is provided).
    return 0
