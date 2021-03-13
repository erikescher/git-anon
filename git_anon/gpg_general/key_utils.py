from collections import OrderedDict

from pgpy import PGPKey
from pgpy.types import SorteDeque


class KeyUtils:

    @staticmethod
    def strip_signatures(key: PGPKey) -> None:
        # pylint: disable=protected-access
        key._signatures = SorteDeque()

    @staticmethod
    def strip_uids(key: PGPKey) -> None:
        # pylint: disable=protected-access
        key._uids = SorteDeque()

    @staticmethod
    def strip_subkeys(key: PGPKey) -> None:
        # pylint: disable=protected-access
        key._children = OrderedDict()

    @staticmethod
    def strip_signatures_uids_subkeys(key: PGPKey):
        # overwrite internal variables in the key to remove unnecessary information
        KeyUtils.strip_subkeys(key)
        KeyUtils.strip_uids(key)
        KeyUtils.strip_signatures(key)
