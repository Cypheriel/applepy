"""Module containing logic responsible for managing the connection to the Apple Push Notification service (APNs)."""
import gzip
import plistlib
import socket
import ssl
import time
from hashlib import sha1
from logging import getLogger
from queue import Queue
from typing import Final

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from applepy.albert import ACTIVATION_INFO_PAYLOAD
from applepy.apns.identifier_map import Status, get_command
from applepy.apns.packet import APNSCommand, APNSItem
from applepy.bags import apns_bag, ids_bag
from applepy.crypto_helper import randbytes, randint
from applepy.ids import PROTOCOL_VERSION
from applepy.ids.payload import generate_id_headers

# noinspection SpellCheckingInspection
COURIER_ID: Final = randint(1, apns_bag.get("APNSCourierHostcount", 50))
COURIER_HOSTNAME: Final = apns_bag.get("APNSCourierHostname", "courier.push.apple.com")
COURIER_HOST: Final = f"{COURIER_ID}-{COURIER_HOSTNAME}"
COURIER_PORT: Final = 5223

ALPN_PROTOCOL: Final = ("apns-security-v3",)

QUERY_KEY: Final = "id-query"
QUERY_URL: Final = ids_bag[QUERY_KEY]

KEEP_ALIVE_INTERVAL: Final = 60  # 1 minute

logger = getLogger(__name__)


class APNSManager:
    """Class whose objects are responsible for managing the connection to the Apple Push Notification service (APNs)."""

    push_notifications: Queue[APNSCommand]
    push_token: bytes
    enabled_topics: list[str]
    selected_topic: str
    courier_stream: ssl.SSLSocket

    def __init__(self: "APNSManager") -> None:
        """Initialize an `APNSManager` object."""
        self.push_notifications: Queue[APNSCommand] = Queue()
        self.push_token: bytes = b""
        self.enabled_topics: list[str] = []
        self.selected_topic: str = "com.apple.madrid"  # TODO: Ensure this is in enabled topics

        sock = socket.create_connection((COURIER_HOST, COURIER_PORT))

        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ssl_context.set_alpn_protocols(ALPN_PROTOCOL)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE

        self.courier_stream = ssl_context.wrap_socket(sock, server_hostname=COURIER_HOST)
        self.courier_stream.settimeout(10)
        self.courier_stream.setblocking(False)
        self.courier_stream.do_handshake()

    def connect(self: "APNSManager", push_key: RSAPrivateKey, push_cert: Certificate) -> None:
        """Connect to the APNs service."""
        logger.info("Connecting to APNs...")
        nonce = b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + randbytes(8)
        signature = b"\x01\x01" + push_key.sign(nonce, PKCS1v15(), SHA1())  # noqa: S303

        APNSCommand(
            command_id=get_command("CONNECT"),
            items=[
                APNSItem(0x02, b"\x01"),
                APNSItem(0x05, 0b01000001.to_bytes(4, "big")),
                APNSItem(0x06, b"\x01"),
                APNSItem(0x08, b"WiFi"),
                APNSItem(0x09, ACTIVATION_INFO_PAYLOAD["ProductVersion"].encode()),
                APNSItem(0x0A, ACTIVATION_INFO_PAYLOAD["BuildVersion"].encode()),
                APNSItem(0x0B, ACTIVATION_INFO_PAYLOAD["ProductType"].encode()),
                APNSItem(0x0C, push_cert.public_bytes(Encoding.DER)),
                APNSItem(0x0D, nonce),
                APNSItem(0x0E, signature),
            ],
        ).write(self.courier_stream)

    def filter_topics(self: "APNSManager", topics: list[str]) -> None:
        """Set the enabled APNs topics."""
        self.enabled_topics = topics

        # TODO: Find a better way to do this
        self.selected_topic = topics[0]

        APNSCommand(
            command_id=get_command("PUSH_TOPICS"),
            items=[
                APNSItem(0x01, self.push_token),
                *(APNSItem(0x02, sha1(topic.encode(), usedforsecurity=False).digest()) for topic in topics),
            ],
        ).write(self.courier_stream)

    def send_notification(self: "APNSManager", payload: bytes) -> int:
        """
        Send a push notification over the APNs.

        :param payload: The payload to send.
        :return: The message ID of the notification that was sent.
        """
        message_id = randbytes(4)

        APNSCommand(
            command_id=get_command("PUSH_NOTIFICATION"),
            items=[
                APNSItem(0x01, sha1(self.selected_topic.encode(), usedforsecurity=False).digest()),
                APNSItem(0x02, self.push_token),
                APNSItem(0x03, payload),
                APNSItem(0x04, message_id),
            ],
        ).write(self.courier_stream)

        return int.from_bytes(message_id, "big")

    def send_notification_ack(self: "APNSManager", message_id: int) -> None:
        """
        Send a push notification acknowledgement.

        :param message_id: The message ID of the notification to acknowledge.
        """
        APNSCommand(
            command_id=get_command("PUSH_NOTIFICATION_ACK"),
            items=[
                APNSItem(0x01, self.push_token),
                APNSItem(0x04, message_id.to_bytes(4, "big")),
                APNSItem(0x08, b"\x00"),
            ],
        ).write(self.courier_stream)

    def send_keepalive(self: "APNSManager") -> None:
        """Send a keepalive command to the APNs."""
        APNSCommand(
            command_id=get_command("KEEP_ALIVE"),
            items=[
                APNSItem(0x01, b"WiFi"),
                APNSItem(0x02, ACTIVATION_INFO_PAYLOAD["ProductVersion"].encode()),
                APNSItem(0x03, ACTIVATION_INFO_PAYLOAD["BuildVersion"].encode()),
                APNSItem(0x04, ACTIVATION_INFO_PAYLOAD["ProductType"].encode()),
            ],
        ).write(self.courier_stream)

    def watchdog(self: "APNSManager", queue: Queue[APNSCommand]) -> None:
        """
        Watch for incoming commands from the APNs.

        :param queue: The queue to put incoming commands into.
        """
        start_time = time.time()
        first_run = True
        while True:
            elapsed_time = time.time() - start_time
            if first_run or elapsed_time >= KEEP_ALIVE_INTERVAL:
                first_run = False
                self.send_keepalive()
                start_time = time.time()

            try:
                self.courier_stream.setblocking(True)
                message = APNSCommand.read(stream=self.courier_stream)
                self.courier_stream.setblocking(False)
                queue.put(message)

            except ssl.SSLWantReadError:
                continue

            time.sleep(0.05)

    def process_commands(self: "APNSManager", queue: Queue[APNSCommand]) -> None:
        """
        Process incoming commands from the APNs.

        :param queue: The queue to get incoming commands from.
        """
        while True:
            message = queue.get()

            if message.command_id == get_command("CONNECT_RESPONSE"):
                if message.get_item_by_alias("STATUS").value != Status.OK:
                    raise Exception("Failed to connect to APNs!")

                logger.info(f"Connected to APNs via {self.courier_stream.server_hostname}!")
                self.push_token = message.get_item_by_alias("PUSH_TOKEN").data

            elif message.command_id == get_command("PUSH_NOTIFICATION"):
                self.send_notification_ack(message.get_item_by_alias("MESSAGE_ID").value)
                self.push_notifications.put(message)

            elif message.command_id == get_command("PUSH_NOTIFICATION_ACK"):
                if message.get_item_by_alias("STATUS").value != Status.OK:
                    logger.error(f"Possible fault with {message.name}: {message.get_item_by_alias('STATUS').value}")

            elif message.command_id == get_command("KEEP_ALIVE_CONFIRMATION") or message.command_id == get_command(
                "NO_STORAGE",
            ):
                continue

            time.sleep(0.1)

    def wait_for_message(self: "APNSManager", target_message_id: int, timeout: int = 30) -> APNSCommand:
        """
        Wait for a message with a given message ID.

        WARNING: This method is presumably useless.
        :param target_message_id: The message ID to wait for.
        :param timeout: The timeout time in seconds.
        :return: The notification with the given message ID.
        """
        start_time = time.time()
        while timeout > time.time() - start_time:
            time.sleep(0.1)
            command = self.push_notifications.get()
            command_id = command.command_id
            if command_id != get_command("PUSH_NOTIFICATION"):
                continue

            message_id = command.get_item_by_alias("MESSAGE_ID")

            if not message_id or message_id != target_message_id:
                self.push_notifications.put(command)
                continue

            return command

        raise TimeoutError(f"Timed out waiting for message {target_message_id}!")

    def query(
        self: "APNSManager",
        handle: str,
        uris: list[str],
        auth_key: RSAPrivateKey,
        registration_cert: Certificate,
    ) -> int:
        """
        Send an APNs participant handle query.

        :param handle: The handle to send the query from.
        :param uris: The URIs to query.
        :param auth_key: The private key used to sign the request.
        :param registration_cert: The certificate sent through the request.
        :return: The message ID of the request.
        """
        logger.info(f"Querying for {uris}...")
        data = {"uris": uris}

        payload = plistlib.dumps(data)
        logger.debug(f"{payload = }")
        compressed_payload = gzip.compress(payload, mtime=0)  # TODO: Figure out if mtime=0 is necessary

        headers = {
            "x-id-self-uri": handle,
            "x-protocol-version": PROTOCOL_VERSION,
            **generate_id_headers(auth_key, registration_cert, QUERY_KEY, self.push_token, payload=compressed_payload),
        }

        logger.debug(f"{headers = }")

        request = {
            "cT": "application/x-apple-plist",
            "U": randbytes(16),
            "c": 96,
            "u": QUERY_URL,
            "h": headers,
            "v": 2,
            "b": compressed_payload,
        }

        logger.debug(f"{request = }")

        return self.send_notification(plistlib.dumps(request, fmt=plistlib.FMT_BINARY))
