# -*- coding: utf-8 -*-
from typing import Type
from uuid import uuid4, uuid5, NAMESPACE_OID

from fido2.cose import CoseKey

from ctap_keyring_device.ctap_private_key_wrapper import CtapPrivateKeyWrapper
from ctap_keyring_device.ctap_strucs import Credential


class CtapCredentialMaker:
    """ This class makes a new credential (key-pair) from the given COSE key type """

    def __init__(self, cose_key_cls: Type[CoseKey]):
        self._cose_key_cls = cose_key_cls

    def make_credential(self, user_id: str) -> Credential:
        """
        Generates a new credential, with a 32-byte id consisting of:
        - uuid5(NAMESPACE_OID, user_id)
        - uuid4, which will be used as the encryption passphrase when encoding the private key

        :param user_id: A user identifier (email, name, uid, ...)
        :return: A new credential holding a generated private key
        """
        assert user_id

        private_key = CtapPrivateKeyWrapper.create(self._cose_key_cls)
        key_password = uuid4().bytes
        user_uuid = uuid5(NAMESPACE_OID, user_id).bytes

        # Having both the user-uuid and key password in the cred id will serve us in the get-assertion flow,
        # for locating a specific user's key and decrypting it
        credential_id = user_uuid + key_password
        return Credential(credential_id, private_key)
