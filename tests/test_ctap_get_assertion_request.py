# -*- coding: utf-8 -*-
import unittest

from ctap_keyring_device.ctap_strucs import CtapGetAssertionRequest, CtapOptions


class TestCtapGetAssertionRequest(unittest.TestCase):
    def test_allow_list_is_empty_list_when_none(self):
        req = CtapGetAssertionRequest.create(
            {CtapGetAssertionRequest.ALLOW_LIST_KEY: None}
        )
        assert req.allow_list == []

    def test_user_verification_required_when_set(self):
        req = CtapGetAssertionRequest.create(
            {CtapGetAssertionRequest.OPTIONS_KEY: {CtapOptions.USER_VERIFICATION: True}}
        )
        assert req.user_verification_required

    def test_user_verification_not_set_when_false(self):
        req = CtapGetAssertionRequest.create(
            {
                CtapGetAssertionRequest.OPTIONS_KEY: {
                    CtapOptions.USER_VERIFICATION: False
                }
            }
        )
        assert not req.user_verification_required

    def test_user_verification_not_set_when_options_not_set(self):
        req = CtapGetAssertionRequest.create({})
        assert not req.user_verification_required

    def test_user_verification_not_set_when_options_is_none(self):
        req = CtapGetAssertionRequest.create(
            {CtapGetAssertionRequest.OPTIONS_KEY: None}
        )
        assert not req.user_verification_required
