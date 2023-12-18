import gzip
import plistlib
import socket
import ssl
import time
from hashlib import sha1
from logging import getLogger
from random import randbytes, randint

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from applepy.albert import ACTIVATION_INFO_PAYLOAD
from applepy.apns.identifier_map import Status, get_command
from applepy.apns.packet import APNSItem, APNSMessage
from applepy.bags import apns_bag, ids_bag
from applepy.ids import PROTOCOL_VERSION
from applepy.ids.payload import generate_id_headers
from applepy.status_codes import StatusCode

# noinspection SpellCheckingInspection
COURIER_ID = randint(1, apns_bag.get("APNSCourierHostcount", 50))
COURIER_HOSTNAME = apns_bag.get(f"APNSCourierHostname", "courier.push.apple.com")
COURIER_HOST = f"{COURIER_ID:02}-{COURIER_HOSTNAME}"
COURIER_PORT = 5223

ALPN_PROTOCOL = ("apns-security-v3",)

QUERY_KEY = "id-query"
QUERY_URL = ids_bag[QUERY_KEY]

logger = getLogger(__name__)


class APNSManager:
    push_token: bytes
    enabled_topics: list[str]
    selected_topic: str = "com.apple.madrid"  # TODO: Ensure this is in enabled topics

    def __init__(self) -> None:
        sock = socket.create_connection((COURIER_HOST, COURIER_PORT))

        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ssl_context.set_alpn_protocols(ALPN_PROTOCOL)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE

        self.courier_stream = ssl_context.wrap_socket(sock, server_hostname=COURIER_HOST)
        self.courier_stream.settimeout(10)
        self.courier_stream.setblocking(False)
        self.courier_stream.do_handshake()

    def connect(self, push_key: RSAPrivateKey, push_cert: Certificate):
        nonce = b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + randbytes(8)
        signature = b"\x01\x01" + push_key.sign(nonce, PKCS1v15(), SHA1())

        APNSMessage(
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

        self.courier_stream.setblocking(True)
        message = APNSMessage.read(stream=self.courier_stream)
        self.courier_stream.setblocking(False)

        status = message.get_item_by_alias("STATUS") if message else None
        if not message or status is None or status.value != Status.OK:
            raise Exception("Failed to connect to APNs!")

        self.push_token = message.get_item_by_alias("PUSH_TOKEN").value

        logger.info(f"Connected to APNs via [cyan]{self.courier_stream.server_hostname}[/]!")

    def filter_topics(self, topics: list[str]):
        self.enabled_topics = topics

        # TODO: Find a better way to do this
        self.selected_topic = topics[0]

        APNSMessage(
            command_id=get_command("PUSH_TOPICS"),
            items=[
                APNSItem(0x01, self.push_token),
                *(APNSItem(0x02, sha1(topic.encode()).digest()) for topic in topics),
            ],
        ).write(self.courier_stream)

    def send_message(self, topic: str, payload: bytes):
        APNSMessage(
            command_id=get_command("PUSH_NOTIFICATION"),
            items=[
                APNSItem(0x01, topic.encode("utf-8")),
                APNSItem(0x02, self.push_token),
                APNSItem(0x03, payload),
                APNSItem(0x04, randbytes(4)),
            ],
        ).write(self.courier_stream)

        message = APNSMessage.read(stream=self.courier_stream)
        if message.command_id != get_command("PUSH_NOTIFICATION_ACK"):
            raise Exception("Failed to send push notification!")
        if not (status := message.get_item_by_alias("STATUS")) or status.value != Status.OK:
            raise Exception("Push notification acknowledgement received with error!")

    def send_keepalive(self):
        APNSMessage(
            command_id=get_command("KEEPALIVE"),
            items=[
                APNSItem(0x01, b"WiFi"),
                APNSItem(0x02, ACTIVATION_INFO_PAYLOAD["ProductVersion"].encode()),
                APNSItem(0x03, ACTIVATION_INFO_PAYLOAD["BuildVersion"].encode()),
                APNSItem(0x04, ACTIVATION_INFO_PAYLOAD["ProductType"].encode()),
            ],
        ).write(self.courier_stream)
        self.courier_stream.setblocking(True)
        APNSMessage.read(stream=self.courier_stream)
        self.courier_stream.setblocking(False)

    def watchdog(self):
        # TODO: Proper threading and signal handling
        start_time = time.time()
        keep_alive_interval = 60  # 1 minute
        first_run = True
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time >= keep_alive_interval or first_run:
                first_run = False
                self.send_keepalive()
                start_time = time.time()

            time.sleep(0.050)

            try:
                APNSMessage.read(stream=self.courier_stream)

            except ssl.SSLWantReadError:
                continue

    def send_notification(self, payload: bytes):
        APNSMessage(
            command_id=get_command("PUSH_NOTIFICATION"),
            items=[
                APNSItem(0x01, sha1(self.selected_topic.encode()).digest()),
                APNSItem(0x02, self.push_token),
                APNSItem(0x03, payload),
                APNSItem(0x04, randbytes(4)),
            ],
        ).write(self.courier_stream)

        ack = self.wait_for_message(get_command("PUSH_NOTIFICATION_ACK"))
        if ack.get_item_by_alias("STATUS").value != Status.OK:
            logger.debug(f"{ack = }")
            raise Exception("Failed to send push notification!")

        return ack

    def wait_for_message(self, command_id: int, timeout: int = 10) -> APNSMessage | None:
        # TODO: *Don't* consume the message if it's not the one we're waiting for
        acknowledged = False
        try:
            start_time = time.time()
            while not acknowledged or time.time() - start_time >= timeout:
                self.courier_stream.setblocking(True)
                message = APNSMessage.read(stream=self.courier_stream)
                self.courier_stream.setblocking(False)
                if message.command_id == command_id:
                    return message
        except ssl.SSLWantReadError:
            return None

    def query(self, handle: str, uris: list[str], auth_key: RSAPrivateKey, registration_cert: Certificate):
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

        ack = self.send_notification(plistlib.dumps(request, fmt=plistlib.FMT_BINARY))
        if ack.get_item_by_alias("STATUS").value != Status.OK:
            logger.debug(f"{ack = }")
            raise Exception("Query failed!")

        response = self.wait_for_message(get_command("PUSH_NOTIFICATION"))

        response_payload = response.get_item_by_alias("PAYLOAD")
        response_plist = response_payload.value
        logger.debug(f"{plistlib.loads(gzip.decompress(plistlib.loads(response_payload.data)['b'])) = }")

        if (status_code := StatusCode(response_plist["status"])) != StatusCode.SUCCESS:
            raise Exception(f"Query failed with {status_code}.")

        return response_plist["results"]
