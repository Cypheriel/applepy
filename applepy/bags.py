import plistlib
from functools import lru_cache
from logging import getLogger
from typing import Final

import requests

logger = getLogger(__name__)


@lru_cache
def get_apns_bag() -> dict[str, str]:
    response = requests.get("https://init.push.apple.com/bag", verify=False)
    if not response.ok:
        raise Exception(f"Failed to fetch APNs bag! Status: {response.status_code}")

    return plistlib.loads(response.content)


@lru_cache
def get_ids_bag() -> dict[str, str]:
    response = requests.get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3", verify=False)
    if response.status_code != 200:
        raise Exception("Failed to fetch IDS bag!")

    return plistlib.loads(plistlib.loads(response.content)["bag"])


apns_bag: Final = get_apns_bag()
ids_bag: Final = get_ids_bag()
