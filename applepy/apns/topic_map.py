"""Maps topic names to their hashes."""
from dataclasses import dataclass
from hashlib import sha1
from logging import getLogger
from typing import Final

logger = getLogger(__name__)


@dataclass
class TopicMap:
    """Dataclass for mapping topic names to their hashes."""

    name: str
    topic_hash: bytes


# TODO: Add more topics
_TOPICS: Final[list[str]] = [
    "com.apple.madrid",
]

_HASHES: Final = [sha1(topic.encode(), usedforsecurity=False).digest() for topic in _TOPICS]

TOPIC_MAP: Final[list[TopicMap]] = [
    TopicMap(
        name=topic,
        topic_hash=topic_hash,
    )
    for topic, topic_hash in zip(_TOPICS, _HASHES)
]


def get_topic_by_hash(topic_hash: bytes) -> str | None:
    """Retrieve a topic by its topic_hash."""
    for topic in TOPIC_MAP:
        if topic.topic_hash == topic_hash:
            return topic.name

    logger.error(f"Topic topic_hash `{topic_hash}` not found in topic map!")

    return None


def get_topic_hash(topic: str) -> bytes | None:
    """Retrieve a topic's topic_hash."""
    for topic in TOPIC_MAP:
        if topic.name == topic:
            return topic.topic_hash

    logger.error(f"Topic `{topic}` not found in topic map!")

    return sha1(topic.encode(), usedforsecurity=False).digest()
