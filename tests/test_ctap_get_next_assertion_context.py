# -*- coding: utf-8 -*-
import unittest

from fido2.ctap import CtapError

from ctap_keyring_device.ctap_strucs import CtapGetNextAssertionContext, Credential


# noinspection PyTypeChecker
class TestCtapGetNextAssertionContext(unittest.TestCase):
    def test_get_next_cred_fails_when_cred_counter_equal_cred_len(self):
        ctx = CtapGetNextAssertionContext(
            request=None, creds=[Credential(b'cred', None)], cred_counter=1
        )
        self.assertRaises(CtapError, ctx.get_next_cred)

    def test_get_next_cred_fails_when_cred_counter_above_cred_len(self):
        ctx = CtapGetNextAssertionContext(
            request=None, creds=[Credential(b'cred', None)], cred_counter=2
        )
        self.assertRaises(CtapError, ctx.get_next_cred)

    def test_get_next_cred_fails_when_timer_is_due(self):
        ctx = CtapGetNextAssertionContext(
            request=None, creds=[Credential(b'cred', None)], cred_counter=0
        )
        ctx.timer -= ctx.TIMEOUT_SECONDS + 5
        self.assertRaises(CtapError, ctx.get_next_cred)

    def test_get_next_creds_sanity(self):
        cred_one, cred_two = Credential(b'cred', None), Credential(b'cred2', None)
        ctx = CtapGetNextAssertionContext(
            request=None, creds=[cred_one, cred_two], cred_counter=0
        )
        assert ctx.get_next_cred() == cred_one
        assert ctx.get_next_cred() == cred_two
        self.assertRaises(CtapError, ctx.get_next_cred)
