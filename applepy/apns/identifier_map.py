"""Module for mapping command and item identifiers to their names and transformed values."""
import gzip
import plistlib
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import partial
from io import BytesIO
from typing import Any, Callable, TypedDict

from cryptography.x509 import load_der_x509_certificate

from applepy.apns.topic_map import get_topic_by_hash

TOKEN_LENGTH = 32
"""The length of a push token in bytes."""
SHA1_LENGTH = 20
"""The length of a SHA1 topic_hash in bytes."""


class Status(Enum):
    """Enum for the status returned by the server in some response items."""

    OK = b"\x00"
    ERROR = b"\x02"


class Interface(Enum):
    """Enum for the interface types sent by the client in the CONNECT command."""

    WIFI = b"\x00"
    CELLULAR = b"\x01"


@dataclass
class Identifier:
    """Dataclass for mapping item identifiers to their semantic aliases and data transformers."""

    name: str
    transformer: Callable[[bytes], Any] | None = None


def get_command(name: str) -> int:
    """Get the command identifier for a given command name."""
    for command_id, command in MAP.items():
        if command["name"] == name:
            return command_id

    raise NotImplementedError(f"Command `{name}` does not exist!")


big_endian = partial(int.from_bytes, byteorder="big")
decode = partial(bytes.decode)


def to_binary_repr(data: bytes) -> str:
    """Convert a byte string to a binary representation."""
    return " ".join(f"{bin(i)[2:]:>08}" for i in data)


def _to_datetime(data: bytes, ms: bool = False, ns: bool = False) -> datetime:
    """Convert a byte string to a datetime object."""
    conversion_factor = 1_000_000_000 if ns else 1_000 if ms else 1
    return datetime.utcfromtimestamp(big_endian(data) / conversion_factor)


to_datetime_ms = partial(_to_datetime, ms=True)
to_datetime_ns = partial(_to_datetime, ns=True)


def to_timedelta(data: bytes) -> timedelta:
    """Convert a byte string to a timedelta object."""
    return timedelta(milliseconds=big_endian(data))


def to_time_from_now(data: bytes) -> datetime:
    """Convert a byte string to a datetime object representing a time from now."""
    return datetime.now() + to_timedelta(data)


def extract_payload(data: bytes) -> dict | None:
    """Extract the payload from a PUSH_NOTIFICATION item."""
    plist = plistlib.loads(data)
    return plistlib.loads(gzip.decompress(plist["b"]))


def b64encode_push_token(data: bytes) -> str:
    """Base-64 encode a push token."""
    return b64encode(data).decode()


def reveal_token_or_topic_hash(data: bytes) -> str:
    """Reveal the token or topic topic_hash from a TOPIC/PUSH_TOKEN item."""
    if len(data) == TOKEN_LENGTH:
        return b64encode_push_token(data)

    if len(data) == SHA1_LENGTH:
        return get_topic_by_hash(data)

    raise Exception("Invalid length for PUSH_TOKEN/TOPIC item!")


@dataclass
class Nonce:
    """Dataclass for a nonce."""

    timestamp: datetime
    random_bytes: bytes

    @classmethod
    def from_bytes(cls: "Nonce", data: bytes) -> "Nonce":
        """Create a nonce from a byte string."""
        stream = BytesIO(data)
        stream.read(1)
        return cls(
            timestamp=datetime.fromtimestamp(big_endian(stream.read(8)) / 1_000),
            random_bytes=stream.read(8),
        )


class MessageMap(TypedDict):
    """Type definition for the message map."""

    name: str
    items: dict[int, Identifier]


MAP: dict[int, MessageMap] = {
    0x07: {
        "name": "CONNECT",
        "items": {
            0x01: Identifier("PUSH_TOKEN", b64encode_push_token),
            0x02: Identifier("STATE"),
            0x05: Identifier("FLAGS", to_binary_repr),
            0x06: Identifier("INTERFACE", Interface),
            0x08: Identifier("CARRIER", decode),
            0x09: Identifier("OS_VERSION", decode),
            0x0A: Identifier("OS_BUILD", decode),
            0x0B: Identifier("HARDWARE_VERSION", decode),
            0x0C: Identifier("CERTIFICATE", load_der_x509_certificate),
            0x0D: Identifier("NONCE", Nonce.from_bytes),
            0x0E: Identifier("SIGNATURE"),
            # 0x10:
            0x11: Identifier("REDIRECT_COUNT", big_endian),
            0x12: Identifier("DNS_RESOLVE_TIME", to_timedelta),
            0x13: Identifier("TSL_HANDSHAKE_TIME", to_timedelta),
        },
    },
    0x08: {
        "name": "CONNECT_RESPONSE",
        "items": {
            0x01: Identifier("STATUS", Status),
            0x02: Identifier("SERVER_METADATA"),  # Requires verification
            0x03: Identifier("PUSH_TOKEN", b64encode_push_token),
            0x04: Identifier("MAX_MESSAGE_SIZE", big_endian),
            0x05: Identifier("PROTOCOL_VERSION(?)", big_endian),  # Requires verification
            0x06: Identifier("CAPABILITIES", to_binary_repr),
            0x07: Identifier("BAD_NONCE_TIME"),  # Requires verification
            0x08: Identifier("LARGE_MESSAGE_SIZE", big_endian),
            0x0A: Identifier("SERVER_TIME", to_datetime_ms),
            0x0B: Identifier("GEO_REGION", decode),
            0x0C: Identifier("UNKNOWN_TIMESTAMP", to_datetime_ms),  # Requires verification
        },
    },
    # TODO: Map topics to their SHA1 hashes
    0x09: {
        "name": "PUSH_TOPICS",
        "items": {
            0x01: Identifier("PUSH_TOKEN", b64encode_push_token),
            0x02: Identifier("ENABLED_TOPIC", get_topic_by_hash),
            0x03: Identifier("DISABLED_TOPIC", get_topic_by_hash),
            0x04: Identifier("OPPORTUNISTIC_TOPIC", get_topic_by_hash),
            0x05: Identifier("PAUSED_TOPIC", get_topic_by_hash),
        },
    },
    0x0A: {
        "name": "PUSH_NOTIFICATION",
        "items": {
            0x01: Identifier("TOPIC/PUSH_TOKEN", reveal_token_or_topic_hash),
            0x02: Identifier("TOPIC/PUSH_TOKEN", reveal_token_or_topic_hash),
            0x03: Identifier("PAYLOAD", extract_payload),
            0x04: Identifier("MESSAGE_ID", big_endian),
            0x05: Identifier("EXPIRATION_DATE", to_time_from_now),
            0x06: Identifier("MESSAGE_TIME", to_datetime_ns),
            # 0x07
            0x09: Identifier("STORAGE_FLAGS", to_binary_repr),  # Requires verification
            0x0D: Identifier("PRIORITY", big_endian),  # Requires verification
            0x0F: Identifier("BASE_TOKEN"),  # Requires verification
            0x15: Identifier("TRACING_UUID", decode),  # Requires verification
            0x18: Identifier("CORRELATION_ID", decode),  # Requires verification
            0x1A: Identifier("APN_FLAGS", to_binary_repr),  # Requires verification
            0x1C: Identifier("PUSH_TYPE"),  # Requires verification
            0x19: Identifier("LAST_RTT"),  # Requires verification
        },
    },
    0x0B: {
        "name": "PUSH_NOTIFICATION_ACK",
        "items": {
            0x01: Identifier("PUSH_TOKEN", b64encode_push_token),
            0x04: Identifier("MESSAGE_ID", big_endian),
            0x08: Identifier("STATUS", Status),
        },
    },
    0x0C: {
        "name": "KEEP_ALIVE",
        "items": {
            0x01: Identifier("CARRIER", decode),  # Requires verification
            0x02: Identifier("OS_VERSION", decode),  # Requires verification
            0x03: Identifier("OS_BUILD", decode),  # Requires verification
            0x04: Identifier("HARDWARE_VERSION", decode),  # Requires verification
            0x05: Identifier("KEEP_ALIVE_INTERVAL", to_timedelta),  # Requires verification
            0x06: Identifier("DELAYED_RESPONSE_INTERVAL", to_timedelta),  # Requires verification
        },
    },
    0x0D: {
        "name": "KEEP_ALIVE_CONFIRMATION",
        "items": {
            0x01: Identifier("STATUS", Status),
        },
    },
    0x0F: {
        "name": "FLUSH",
        "items": {
            0x01: Identifier("PADDING", big_endian),
        },
    },
    0x0E: {
        "name": "NO_STORAGE",
        "items": {
            0x01: Identifier("PUSH_TOKEN", b64encode_push_token),
        },
    },
}
"""Map of command identifiers to their semantic aliases and supported items with their aliases and data transformers."""


def _get_name(command_id: int) -> str:
    """
    Get the command name for a given command identifier.

    :return: The command name, or "UNKNOWN(0xXX)" if the command identifier is not known.
    """
    try:
        return MAP[command_id]["name"]
    except KeyError:
        return f"UNKNOWN(0x{command_id:02x})"
