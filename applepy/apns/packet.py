"""Module containing APNs packet serialization and deserialization classes."""
from dataclasses import dataclass
from functools import cached_property
from io import BytesIO
from logging import getLogger
from socket import socket
from typing import Callable, Type, TypeVar

from applepy.apns.identifier_map import MAP, _get_name, get_command

T = TypeVar("T")

logger = getLogger(__name__)


@dataclass
class APNSItem:
    """Represents a single item in an APNs command."""

    item_id: int
    data: bytes
    command_id: int = -1

    def __post_init__(self: "APNSItem") -> None:
        """Set the name override to an empty string."""
        self.name_override: str = ""

    @cached_property
    def name(self: "APNSItem") -> str:
        """Get the alias of the item, or the hex representation if it is unknown."""
        try:
            return self.name_override or MAP[self.command_id]["items"][self.item_id].name
        except (KeyError, IndexError):
            return f"UNKNOWN(0x{self.item_id:02x})"

    def _transform_data(self: "APNSItem", transformer: Callable[[bytes], T]) -> T:
        """Transform the data using a transformer callback if one exists."""
        return transformer(self.data)

    @cached_property
    def value(self: "APNSItem") -> object | bytes:
        """The value of the item, transformed if a transformer exists."""
        identifier = MAP.get(self.command_id, {}).get("items", {}).get(self.item_id, None)

        if identifier is None or identifier.transformer is None:
            return self.data

        return self._transform_data(identifier.transformer)

    @classmethod
    def read(cls: Type["APNSItem"], stream: BytesIO, command_id: int) -> "APNSItem":
        """Deserialize an item from a BytesIO stream."""
        item_id = int.from_bytes(stream.read(1), "big")
        data_length = int.from_bytes(stream.read(2), "big")
        data = stream.read(data_length)

        if len(data) != data_length:
            raise Exception("Expected item data length does not match actual length!")

        return cls(item_id, data, command_id=command_id)

    def __bytes__(self: "APNSItem") -> bytes:
        """Serialize the item to bytes."""
        return self.item_id.to_bytes(1, "big") + len(self.data).to_bytes(2, "big") + self.data


@dataclass
class APNSCommand:
    """Dataclass representing an APNs command."""

    command_id: int
    items: list[APNSItem]

    @property
    def name(self: "APNSCommand") -> str:
        """The semantic alias of the command."""
        return _get_name(self.command_id)

    def __post_init__(self: "APNSCommand") -> None:
        """Set the command_id of all items to the command_id of the command."""
        for item in self.items:
            item.command_id = self.command_id

    @classmethod
    def read(cls: Type["APNSCommand"], stream: socket) -> "APNSCommand":
        """Attempt to read and deserialize command from a socket."""
        command_id = int.from_bytes(stream.recv(1), "big")
        payload_length = int.from_bytes(stream.recv(4), "big")
        payload = BytesIO(stream.recv(payload_length))

        items = []
        while payload.tell() < payload_length:
            items.append(APNSItem.read(payload, command_id))

        debug_message = f"Received packet {_get_name(command_id)} ({command_id}):"

        for item in items:
            if command_id == get_command("PUSH_NOTIFICATION"):
                match item.item_id:
                    case 0x01:
                        item.name_override = "PUSH_TOKEN"
                    case 0x02:
                        item.name_override = "TOPIC"

            debug_message += f"\n    {item.name}: {item.value}"

        logger.debug(debug_message)

        return cls(command_id, items)

    def write(self: "APNSCommand", stream: socket) -> None:
        """Serialize and send the command to the stream."""
        stream.send(bytes(self))

        debug_message = f"Sending packet {self.name} ({self.command_id}):"

        for item in self.items:
            if self.command_id == get_command("PUSH_NOTIFICATION"):
                match item.item_id:
                    case 0x01:
                        item.name_override = "TOPIC"
                    case 0x02:
                        item.name_override = "PUSH_TOKEN"

            debug_message += f"\n    {item.name}: {item.value}"

        logger.debug(debug_message)

    def get_item_by_alias(self: "APNSCommand", alias: str) -> APNSItem | None:
        """Get an item by its semantic alias."""
        for item in self.items:
            if item.name == alias:
                return item

        return None

    def get_item_by_id(self: "APNSCommand", item_id: int) -> APNSItem | None:
        """Get an item by its identifier."""
        for item in self.items:
            if item.item_id == item_id:
                return item

        raise Exception(f"Item `0x{item_id:02x}` not found!")

    def __bytes__(self: "APNSCommand") -> bytes:
        """Serialize the command to bytes."""
        payload = b"".join(bytes(item) for item in self.items)
        return self.command_id.to_bytes(1, "big") + len(payload).to_bytes(4, "big") + payload

    def __hash__(self: "APNSCommand") -> int:
        """Make the command hashable via its serialized bytes."""
        return hash(bytes(self))
