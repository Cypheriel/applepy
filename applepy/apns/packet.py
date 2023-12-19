from dataclasses import dataclass
from functools import cached_property
from io import BytesIO
from logging import getLogger
from socket import socket

from applepy.apns.identifier_map import MAP, _get_name

logger = getLogger(__name__)


@dataclass
class APNSItem:
    item_id: int
    data: bytes
    command_id: int = -1

    @cached_property
    def name(self):
        try:
            return MAP[self.command_id]["items"][self.item_id].name
        except (KeyError, IndexError):
            return f"UNKNOWN(0x{self.item_id:02x})"

    @cached_property
    def value(self):
        try:
            transformer = MAP[self.command_id]["items"][self.item_id].transformer
        except (KeyError, IndexError):
            return self.data

        if transformer is None:
            return self.data

        return transformer(self.data)

    @classmethod
    def read(cls, stream: BytesIO, command_id: int) -> "APNSItem":
        item_id = int.from_bytes(stream.read(1), "big")
        data_length = int.from_bytes(stream.read(2), "big")
        data = stream.read(data_length)

        if len(data) != data_length:
            raise Exception("Expected item data length does not match actual length!")

        return cls(item_id, data, command_id=command_id)

    def __bytes__(self) -> bytes:
        return self.item_id.to_bytes(1, "big") + len(self.data).to_bytes(2, "big") + self.data


@dataclass
class APNSMessage:
    command_id: int
    items: list[APNSItem]

    @property
    def name(self):
        return _get_name(self.command_id)

    def __post_init__(self) -> None:
        for item in self.items:
            item.command_id = self.command_id

    @classmethod
    def read(cls, stream: socket):
        command_id = int.from_bytes(stream.recv(1), "big")
        payload_length = int.from_bytes(stream.recv(4), "big")
        payload = BytesIO(stream.recv(payload_length))

        items = []
        while payload.tell() < payload_length:
            items.append(APNSItem.read(payload, command_id))

        debug_message = f"[red]Received[/] packet [yellow]{_get_name(command_id)}[/] ({command_id}):\n"
        for item in items:
            debug_message += f"    {item.name}: {item.value}\n"
        logger.debug(debug_message)

        return cls(command_id, items)

    def write(self, stream: socket):
        stream.send(bytes(self))

        debug_message = f"[cyan]Sending[/] packet [yellow]{self.name}[/] ({self.command_id}):"

        for item in self.items:
            debug_message += f"\n    {item.name}: {item.value}"
        logger.debug(debug_message)

    def get_item_by_alias(self, alias: str) -> APNSItem:
        for item in self.items:
            if item.name == alias:
                return item

        raise Exception(f"Item `{alias}` not found!")

    def get_item_by_id(self, item_id: int) -> APNSItem | None:
        for item in self.items:
            if item.item_id == item_id:
                return item

        raise Exception(f"Item `0x{item_id:02x}` not found!")

    def __bytes__(self) -> bytes:
        payload = b"".join(bytes(item) for item in self.items)
        return self.command_id.to_bytes(1, "big") + len(payload).to_bytes(4, "big") + payload
