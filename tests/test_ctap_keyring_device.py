# -*- coding: utf-8 -*-
import hashlib
import unittest
from typing import Optional, List
from uuid import uuid4

import keyring
from fido2 import ctap2, webauthn, cose, cbor
from fido2.attestation import PackedAttestation
from fido2.client import ClientData, WEBAUTHN_TYPE
from fido2.ctap import CtapError
from fido2.hid import CTAPHID
from fido2.utils import websafe_encode
from fido2.webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialUserEntity,
)
from keyring.backend import KeyringBackend

from ctap_keyring_device.ctap_credential_maker import CtapCredentialMaker
from ctap_keyring_device.ctap_keyring_device import CtapKeyringDevice
from ctap_keyring_device.ctap_strucs import (
    CtapOptions,
    CtapMakeCredentialRequest,
    CtapGetAssertionRequest,
)


class InMemKeyring(KeyringBackend):
    def __init__(self):
        self.store = {}

    def get_password(self, service, username):
        key = self._get_password_key(service, username)
        return self.store[key]

    def set_password(self, service, username, password):
        key = self._get_password_key(service, username)
        self.store[key] = password

    @staticmethod
    def _get_password_key(service, username):
        return service + '-' + username


class TestCtapKeyringDevice(unittest.TestCase):
    def setUp(self) -> None:
        self._dev = CtapKeyringDevice()
        self._keyring = InMemKeyring()
        self._cred_maker = CtapCredentialMaker(cose.RS256)

        keyring.set_keyring(self._keyring)

    def test_capabilities_include_cbor(self):
        assert self._dev.capabilities & ctap2.CAPABILITY.CBOR

    def test_info(self):
        info = self._dev.get_info()
        assert info.aaguid == self._dev.AAGUID
        assert (
            info.options
            and info.options[CtapOptions.PLATFORM_DEVICE]
            and info.options[CtapOptions.RESIDENT_KEY]
            and info.options[CtapOptions.USER_PRESENCE]
            and info.options[CtapOptions.USER_VERIFICATION]
        )
        assert info.max_msg_size == self._dev.MAX_MSG_SIZE
        assert (
            len(info.transports) == 1
            and info.transports[0] == webauthn.AuthenticatorTransport.INTERNAL
        )
        assert info.algorithms == cose.CoseKey.supported_algorithms()

    def test_make_credential_fails_if_cred_in_exclude_list(self):
        excluded_rp_id = 'excluded.rp.com'
        excluded_user_id = uuid4()
        cred_maker = CtapCredentialMaker(cose.RS256)
        excluded_cred = cred_maker.make_credential(excluded_user_id.hex)

        req = self._get_make_credential_request(
            rp_id=excluded_rp_id, excluded_cred_ids=[excluded_cred.id]
        )
        self._keyring.set_password(
            self._dev.get_service_name(excluded_rp_id),
            excluded_cred.user_id,
            excluded_cred.encoded,
        )

        try:
            self._dev.make_credential(req)
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.CREDENTIAL_EXCLUDED

    def test_make_credential_fails_if_cred_params_are_missing(self):
        req = self._get_make_credential_request()
        req.pop(CtapMakeCredentialRequest.PUBLIC_KEY_CREDENTIAL_PARAMS_KEY)

        try:
            self._dev.make_credential(req)
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.MISSING_PARAMETER

    def test_make_credential_fails_for_blank_user_id(self):
        req = self._get_make_credential_request(user_id='')

        try:
            self._dev.make_credential(req)
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.MISSING_PARAMETER

    def test_make_credential_fails_for_blank_rp_id(self):
        req = self._get_make_credential_request(rp_id='')

        try:
            self._dev.make_credential(req)
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.MISSING_PARAMETER

    def test_keyring_set_sanity(self):
        self.keyring_set_sanity(user_id='danny@pasten.com')

    def test_keyring_set_sanity_unicode_user_id(self):
        self.keyring_set_sanity(user_id='דני@פסטן.קום')

    def keyring_set_sanity(self, user_id):
        algorithm, rp_id = cose.RS256.ALGORITHM, 'pasten.com'
        req = self._get_make_credential_request(
            algorithm=algorithm, rp_id=rp_id, user_id=user_id
        )
        attestation_object = self._dev.make_credential(req)

        assert attestation_object.fmt == PackedAttestation.FORMAT

        assert 'alg' in attestation_object.att_statement
        assert attestation_object.att_statement['alg'] == algorithm

        assert (
            attestation_object.auth_data.rp_id_hash
            == hashlib.sha256(rp_id.encode('utf-8')).digest()
        )

        assert attestation_object.auth_data.credential_data is not None
        assert attestation_object.auth_data.credential_data.aaguid == self._dev.AAGUID

        assert len(self._keyring.store) == 1

    def test_get_next_assertion_fails_if_next_assertion_context_is_not_set(self):
        try:
            self._dev.get_next_assertion()
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.NOT_ALLOWED

    def test_get_assertion_fails_if_allow_list_is_empty(self):
        req = self._get_assertion_request()

        try:
            self._dev.get_assertion(req)
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.MISSING_PARAMETER

    def test_get_assertion_fails_if_cred_is_not_found(self):
        req = self._get_assertion_request(allowed_cred_ids=[b'1337'.zfill(32)])

        try:
            self._dev.get_assertion(req)
            assert False
        except CtapError as e:
            assert e.code == CtapError.ERR.NO_CREDENTIALS

    def test_get_assertion_skips_invalid_credential_ids(self):
        credential_maker = CtapCredentialMaker(cose.RS256)
        user_id = 'danny@pasten.com'
        cred = credential_maker.make_credential(user_id=user_id)

        rp_id = 'pasten.com'
        self._keyring.set_password(
            self._dev.get_service_name(rp_id), cred.user_id, cred.encoded
        )

        req = self._get_assertion_request(
            rp_id=rp_id, allowed_cred_ids=[b'1337', cred.id]
        )

        self._dev.get_assertion(req)
        self.assertRaises(CtapError, self._dev.get_next_assertion)

    def test_get_assertion_skips_invalid_credential_algorithms(self):
        cred = self._cred_maker.make_credential(user_id='danny@pasten.com')

        rp_id = 'pasten.com'
        self._keyring.set_password(
            self._dev.get_service_name(rp_id), cred.user_id, cred.encoded
        )

        second_cred = self._cred_maker.make_credential(user_id='danny@pistun.com')
        second_cred.private_key.get_algorithm = lambda: 1337
        self._keyring.set_password(
            self._dev.get_service_name(rp_id), second_cred.user_id, second_cred.encoded
        )

        req = self._get_assertion_request(
            rp_id=rp_id, allowed_cred_ids=[cred.id, second_cred.id]
        )

        self._dev.get_assertion(req)
        self.assertRaises(CtapError, self._dev.get_next_assertion)

    def test_get_assertion_skips_invalid_encoded_credentials(self):
        cred = self._cred_maker.make_credential(user_id='danny@pasten.com')

        rp_id = 'pasten.com'
        self._keyring.set_password(
            self._dev.get_service_name(rp_id), cred.user_id, cred.encoded
        )

        second_cred = self._cred_maker.make_credential(user_id='danny@pistun.com')
        self._keyring.set_password(
            self._dev.get_service_name(rp_id),
            second_cred.user_id,
            second_cred.encoded[:30],
        )

        req = self._get_assertion_request(
            rp_id=rp_id, allowed_cred_ids=[cred.id, second_cred.id]
        )

        self._dev.get_assertion(req)
        self.assertRaises(CtapError, self._dev.get_next_assertion)

    def test_get_next_assertion_sanity(self):
        rp_id = 'pasten.com'

        cred_ids = []
        for user_id in ['danny@pasten.com', 'danny@pistun.com', 'danny@mefasten.com']:
            cred = self._cred_maker.make_credential(user_id=user_id)
            cred_ids.append(cred.id)
            self._keyring.set_password(
                self._dev.get_service_name(rp_id), cred.user_id, cred.encoded
            )

        req = self._get_assertion_request(rp_id=rp_id, allowed_cred_ids=cred_ids)

        assertion = self._dev.get_assertion(req)
        assert assertion.number_of_credentials == 3

        self._dev.get_next_assertion()
        self._dev.get_next_assertion()
        self.assertRaises(CtapError, self._dev.get_next_assertion)

    def test_failure_on_non_cbor_cmd(self):
        res = self._dev.call(CTAPHID.PING)
        assert res == CtapError.ERR.INVALID_COMMAND.to_bytes(1, 'big')

    def test_failure_on_cbor_cmd_with_no_data(self):
        res = self._dev.call(CTAPHID.CBOR, data=b'')
        assert res == CtapError.ERR.INVALID_PARAMETER.to_bytes(1, 'big')

    def test_failure_on_unsupported_ctap_cmd(self):
        res = self._dev.call(
            CTAPHID.CBOR, data=ctap2.CTAP2.CMD.CLIENT_PIN.to_bytes(1, 'big')
        )
        assert res == CtapError.ERR.INVALID_COMMAND.to_bytes(1, 'big')

    def test_failure_on_malformed_cbor_data(self):
        res = self._dev.call(
            CTAPHID.CBOR,
            data=ctap2.CTAP2.CMD.MAKE_CREDENTIAL.to_bytes(1, 'big') + b'malformed',
        )
        assert res == CtapError.ERR.INVALID_CBOR.to_bytes(1, 'big')

    def test_failure_on_non_dict_cbor_data(self):
        res = self._dev.call(
            CTAPHID.CBOR,
            data=ctap2.CTAP2.CMD.MAKE_CREDENTIAL.to_bytes(1, 'big')
            + cbor.encode('str'),
        )
        assert res == CtapError.ERR.INVALID_CBOR.to_bytes(1, 'big')

    @staticmethod
    def _get_make_credential_request(
        algorithm: int = cose.RS256.ALGORITHM,
        user_id: str = 'danny@pasten.com',
        user_name: str = 'pasten',
        rp_id: str = 'pasten.com',
        rp_name: str = 'Pasten LTD',
        client_data: Optional[ClientData] = None,
        excluded_cred_ids: Optional[List[bytes]] = None,
    ) -> dict:

        client_data = client_data or ClientData.build(
            typ=WEBAUTHN_TYPE.MAKE_CREDENTIAL,
            origin=rp_id,
            challenge=websafe_encode(b'pasten-challenge'),
        )

        req = {
            CtapMakeCredentialRequest.CLIENT_DATA_HASH_KEY: hashlib.sha256(
                client_data
            ).digest(),
            CtapMakeCredentialRequest.RP_KEY: PublicKeyCredentialRpEntity(
                rp_id, rp_name
            ),
            CtapMakeCredentialRequest.USER_KEY: PublicKeyCredentialUserEntity(
                user_id, user_name
            ),
            CtapMakeCredentialRequest.PUBLIC_KEY_CREDENTIAL_PARAMS_KEY: [
                PublicKeyCredentialParameters(
                    PublicKeyCredentialType.PUBLIC_KEY, algorithm
                )
            ],
        }

        if excluded_cred_ids:
            req[CtapMakeCredentialRequest.EXCLUDE_LIST_KEY] = [
                PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY, cred_id
                )
                for cred_id in excluded_cred_ids
            ]

        return req

    @staticmethod
    def _get_assertion_request(
        rp_id: str = 'pasten.com',
        client_data: Optional[ClientData] = None,
        allowed_cred_ids: Optional[List[bytes]] = None,
        user_verification_required=False,
    ) -> dict:

        client_data = client_data or ClientData.build(
            typ=WEBAUTHN_TYPE.GET_ASSERTION,
            origin=rp_id,
            challenge=websafe_encode(b'pasten-challenge'),
        )
        req = {
            CtapGetAssertionRequest.RP_ID_KEY: rp_id,
            CtapGetAssertionRequest.CLIENT_DATA_HASH_KEY: client_data.hash,
        }

        if user_verification_required:
            req[CtapGetAssertionRequest.OPTIONS_KEY] = {
                CtapOptions.USER_VERIFICATION: True
            }

        if allowed_cred_ids:
            req[CtapGetAssertionRequest.ALLOW_LIST_KEY] = [
                PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY, cred_id
                )
                for cred_id in allowed_cred_ids
            ]

        return req
