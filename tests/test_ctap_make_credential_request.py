# -*- coding: utf-8 -*-
import unittest

from ctap_keyring_device.ctap_strucs import CtapMakeCredentialRequest, CtapOptions


class TestCtapMakeCredentialRequest(unittest.TestCase):
    def test_resident_key_required_when_set(self):
        req = CtapMakeCredentialRequest.create(
            {CtapMakeCredentialRequest.OPTIONS_KEY: {CtapOptions.RESIDENT_KEY: True}}
        )
        assert req.resident_key_required

    def test_resident_key_not_set_when_false(self):
        req = CtapMakeCredentialRequest.create(
            {CtapMakeCredentialRequest.OPTIONS_KEY: {CtapOptions.RESIDENT_KEY: False}}
        )
        assert not req.resident_key_required

    def test_resident_key_not_set_when_options_not_set(self):
        req = CtapMakeCredentialRequest.create({})
        assert not req.resident_key_required

    def test_resident_key_not_set_when_options_is_none(self):
        req = CtapMakeCredentialRequest.create(
            {CtapMakeCredentialRequest.OPTIONS_KEY: None}
        )
        assert not req.resident_key_required

    def test_user_verification_required_when_set(self):
        req = CtapMakeCredentialRequest.create(
            {
                CtapMakeCredentialRequest.OPTIONS_KEY: {
                    CtapOptions.USER_VERIFICATION: True
                }
            }
        )
        assert req.user_verification_required

    def test_user_verification_not_set_when_false(self):
        req = CtapMakeCredentialRequest.create(
            {
                CtapMakeCredentialRequest.OPTIONS_KEY: {
                    CtapOptions.USER_VERIFICATION: False
                }
            }
        )
        assert not req.user_verification_required

    def test_user_verification_not_set_when_options_not_set(self):
        req = CtapMakeCredentialRequest.create({})
        assert not req.user_verification_required

    def test_user_verification_not_set_when_options_is_none(self):
        req = CtapMakeCredentialRequest.create(
            {CtapMakeCredentialRequest.OPTIONS_KEY: None}
        )
        assert not req.user_verification_required

    def test_exclude_list_is_empty_list_when_none(self):
        req = CtapMakeCredentialRequest.create(
            {CtapMakeCredentialRequest.EXCLUDE_LIST_KEY: None}
        )
        assert req.exclude_list == []
