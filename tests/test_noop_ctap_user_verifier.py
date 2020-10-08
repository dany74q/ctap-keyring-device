# -*- coding: utf-8 -*-
import unittest

from ctap_keyring_device.ctap_user_verifiers import NoopCtapUserVerifier


class TestNoopCtapUserVerifier(unittest.TestCase):
    def test_available_is_true(self):
        assert NoopCtapUserVerifier.available()

    def test_verify_user_is_true(self):
        assert NoopCtapUserVerifier().verify_user('')
