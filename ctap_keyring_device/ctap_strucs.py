# -*- coding: utf-8 -*-
import base64
from typing import List

from cryptography.hazmat.primitives import serialization
from fido2 import cose
from fido2.ctap import CtapError
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor,
)

from ctap_keyring_device.ctap_private_key_wrapper import CtapPrivateKeyWrapper

from timeit import default_timer as timer


class CtapOptions:
    PLATFORM_DEVICE = 'plat'
    RESIDENT_KEY = 'rk'
    CLIENT_PIN = 'clientPin'
    USER_PRESENCE = 'up'
    USER_VERIFICATION = 'uv'


class Credential:
    """ Represents a ctap-saved credential - with a credential id, private key, and a COSE algorithm. """

    def __init__(self, credential_id: bytes, private_key: CtapPrivateKeyWrapper):
        self.id = credential_id
        self.private_key = private_key
        self._encoded = None

    @property
    def algorithm(self):
        return self.private_key.get_algorithm()

    @property
    def cose_key(self):
        cose_key_cls = cose.CoseKey.for_alg(self.algorithm)

        public_key = self.private_key.get_public_key()
        return cose_key_cls.from_cryptography_key(public_key)

    @property
    def user_id(self) -> str:
        return self.id[:16].hex()

    @property
    def password(self) -> bytes:
        return self.id[16:]

    @property
    def encoded(self) -> str:
        if self._encoded:
            return self._encoded

        key_bytes = self.private_key.get_key().private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password=self.password
            ),
        )

        alg = int(self.algorithm).to_bytes(2, 'big', signed=True)

        self._encoded = str(base64.b64encode(alg + key_bytes), 'utf-8')
        return self._encoded


class CtapMakeCredentialRequest:
    """ Represents the cbor encoded MAKE_CREDENTIAL request """

    CLIENT_DATA_HASH_KEY = 1
    RP_KEY = 2
    USER_KEY = 3
    PUBLIC_KEY_CREDENTIAL_PARAMS_KEY = 4
    EXCLUDE_LIST_KEY = 5
    EXTENSIONS_KEY = 6
    OPTIONS_KEY = 7
    PIN_AUTH_KEY = 8
    PIN_PROTOCOL_KEY = 9

    def __init__(
        self,
        client_data_hash: bytes,
        rp: PublicKeyCredentialRpEntity,
        user: PublicKeyCredentialUserEntity,
        public_key_credential_params: List[PublicKeyCredentialParameters],
        exclude_list: List[PublicKeyCredentialDescriptor],
        extensions: dict,
        options: dict,
        pin_auth: bytes,
        pin_protocol: int,
    ):
        self.client_data_hash = client_data_hash
        self.rp = rp
        self.user = user
        self.public_key_credential_params = public_key_credential_params
        self.exclude_list = exclude_list or []
        self.resident_key_required = (
            options.get(CtapOptions.RESIDENT_KEY) if options else False
        )
        self.user_verification_required = (
            options.get(CtapOptions.USER_VERIFICATION) if options else False
        )
        self.options = options

        # Not utilized, here for reference
        self.extensions = extensions
        self.pin_auth = pin_auth
        self.pin_protocol = pin_protocol

    @classmethod
    def create(cls, make_credential_request: dict):
        # noinspection PyProtectedMember
        return CtapMakeCredentialRequest(
            client_data_hash=make_credential_request.get(cls.CLIENT_DATA_HASH_KEY),
            rp=PublicKeyCredentialRpEntity._wrap(
                make_credential_request.get(cls.RP_KEY)
            ),
            user=PublicKeyCredentialUserEntity._wrap(
                make_credential_request.get(cls.USER_KEY)
            ),
            public_key_credential_params=PublicKeyCredentialParameters._wrap_list(
                make_credential_request.get(cls.PUBLIC_KEY_CREDENTIAL_PARAMS_KEY)
            ),
            exclude_list=PublicKeyCredentialDescriptor._wrap_list(
                make_credential_request.get(cls.EXCLUDE_LIST_KEY)
            ),
            extensions=make_credential_request.get(cls.EXTENSIONS_KEY),
            options=make_credential_request.get(cls.OPTIONS_KEY),
            pin_auth=make_credential_request.get(cls.PIN_AUTH_KEY),
            pin_protocol=make_credential_request.get(cls.PIN_PROTOCOL_KEY),
        )


class CtapGetAssertionRequest:
    """ Represents the cbor encoded GET_ASSERTION request """

    RP_ID_KEY = 1
    CLIENT_DATA_HASH_KEY = 2
    ALLOW_LIST_KEY = 3
    EXTENSIONS_KEY = 4
    OPTIONS_KEY = 5
    PIN_AUTH_KEY = 6
    PIN_PROTOCOL_KEY = 7

    def __init__(
        self,
        rp_id: str,
        client_data_hash: bytes,
        allow_list: List[PublicKeyCredentialDescriptor],
        extensions: dict,
        options: dict,
        pin_auth: bytes,
        pin_protocol: int,
    ):
        self.rp_id = rp_id
        self.client_data_hash = client_data_hash
        self.allow_list = allow_list or []
        self.user_verification_required = (
            options.get(CtapOptions.USER_VERIFICATION) if options else False
        )
        self.options = options

        # Not utilized, here for reference
        self.extensions = extensions
        self.pin_auth = pin_auth
        self.pin_protocol = pin_protocol

    @classmethod
    def create(cls, get_assertion_req: dict):
        # noinspection PyProtectedMember
        return CtapGetAssertionRequest(
            rp_id=get_assertion_req.get(cls.RP_ID_KEY),
            client_data_hash=get_assertion_req.get(cls.CLIENT_DATA_HASH_KEY),
            allow_list=PublicKeyCredentialDescriptor._wrap_list(
                get_assertion_req.get(cls.ALLOW_LIST_KEY)
            ),
            extensions=get_assertion_req.get(cls.EXTENSIONS_KEY),
            options=get_assertion_req.get(cls.OPTIONS_KEY),
            pin_auth=get_assertion_req.get(cls.PIN_AUTH_KEY),
            pin_protocol=get_assertion_req.get(cls.PIN_PROTOCOL_KEY),
        )


class CtapGetNextAssertionContext:
    """
    A context which is saved between get-assertion and get-next-assertion requests,
    when multiple credentials are matched
    """

    TIMEOUT_SECONDS = 30

    def __init__(
        self,
        request: CtapGetAssertionRequest,
        creds: List[Credential],
        cred_counter: int,
    ):
        self.request = request
        self.creds = creds
        self.cred_counter = cred_counter

        self.timer = timer()

    def get_next_cred(self) -> Credential:
        if self.cred_counter >= len(self.creds):
            raise CtapError(CtapError.ERR.NOT_ALLOWED)

        if timer() - self.timer > self.TIMEOUT_SECONDS:
            raise CtapError(CtapError.ERR.NOT_ALLOWED)

        try:
            return self.creds[self.cred_counter]
        finally:
            self.timer = timer()
            self.cred_counter += 1
