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
from applepy.logging import setup_logging, log_file, upload_log, file_handler

setup_logging()
logger = getLogger("applepy")
apns = APNSManager()


def entrypoint(func: Callable[..., int]) -> None:
    logger.info(f"Writing log to temporary file: {log_file.name}")

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
    logger.debug(f"APNs bag: {apns_bag}")
    logger.debug(f"IDS bag: {ids_bag}")

    push_key, push_cert = request_push_cert()
    apns.connect(push_key, push_cert)
    apns.filter_topics(["com.apple.madrid"])
    profile_id, auth_token = auth_user()
    auth_key, auth_cert = auth_device(profile_id, auth_token)
    handles = get_handles(profile_id, push_key, push_cert, auth_key, auth_cert, apns.push_token)
    registration_cert = register(profile_id, push_key, push_cert, auth_key, auth_cert, apns.push_token, handles)
    results = apns.query(handles[0]["uri"], [input("Handle: ")], auth_key, registration_cert)
    logger.info(f"Received response from APNs query: {results}")
    return 0
