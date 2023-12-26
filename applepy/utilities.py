"""Module for generic utilities used across the project."""


def to_length_value(data: bytes, length: int = 4) -> bytes:
    """Prepend the length of the data to the data."""
    return len(data).to_bytes(length, "big") + data
