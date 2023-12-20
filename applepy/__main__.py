"""Entry point for the application script."""
import os
import sys
import time
from logging import getLogger
from queue import Queue
from threading import Thread
from typing import Callable

from rich.prompt import Confirm, Prompt

from applepy.albert import request_push_cert
from applepy.apns.manager import APNSManager
from applepy.apns.packet import APNSCommand
from applepy.bags import apns_bag, ids_bag
from applepy.ids.auth import auth_device, auth_user, get_handles
from applepy.ids.registration import register
from applepy.init_logging import LOG_FILE_PATH, setup_logging, upload_log
from applepy.status_codes import StatusCode

APNS_TIMEOUT = 30

file_handler = setup_logging()
logger = getLogger(__name__)
apns = APNSManager()


def entrypoint(func: Callable[..., int]) -> None:
    """General boilerplate for entrypoint functions such as `main()`."""
    logger.info(f"Writing log to temporary file: {LOG_FILE_PATH.name}")

    exit_code = 0

    try:
        exit_code = func() or 0

    except KeyboardInterrupt:
        exit_code = 127

    except Exception as e:
        logger.exception(e)
        exit_code = 1

    finally:
        to_upload_log = {"0": False, "1": False}.get(os.getenv("UPLOAD_LOG"), None)
        if to_upload_log in (True, None):
            logger.warning(
                "Log file may contain sensitive information. Please be cautious about who you share this with!",
            )
        if (to_upload_log is True) or ((to_upload_log is None) and Confirm.ask("Upload log file?")):
            url = upload_log()
            logger.info(f"Uploaded log: {url}")

        apns.courier_stream.close()

        file_handler.close()
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

    # Set up APNs watchdog and processing threads
    command_queue: Queue[APNSCommand] = Queue()
    watchdog = Thread(target=apns.watchdog, args=(command_queue,), daemon=True)
    processor = Thread(target=apns.process_commands, args=(command_queue,), daemon=True)

    watchdog.start()
    processor.start()

    # Wait for the APNs connection to be established, as signaled by the receipt of a push token.
    start_time = time.time()
    while not apns.push_token:
        if time.time() - start_time > APNS_TIMEOUT:
            raise TimeoutError("Failed to obtain push token after 30 seconds.")

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

    # Query the identities tied to a handle of the user's choice (or the own user if "self" is provided).
    handle_to_test = handle if (handle := input("Handle: ").strip().lower()) != "self" else handles[0]["uri"]
    apns.query(handles[0]["uri"], [handle_to_test], auth_key, registration_cert)

    # Attempt to retrieve the response to the query. This will block until a response is received.
    query_response = apns.push_notifications.get()

    query_status = StatusCode(query_response.get_item_by_alias("PAYLOAD").value.get("status", -1))
    if query_status != StatusCode.SUCCESS:
        logger.error(f"Query failed with status code: {query_status}")
        return 1

    Prompt.ask("Press [Enter] to exit...")
    return 0
