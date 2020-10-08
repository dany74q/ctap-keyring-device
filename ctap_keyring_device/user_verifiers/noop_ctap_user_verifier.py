# -*- coding: utf-8 -*-
from ctap_keyring_device.user_verifiers.ctap_user_verifier import CtapUserVerifierBase


class NoopCtapUserVerifier(CtapUserVerifierBase):
    """ Dummy verifier - always returns true """

    def _available(self) -> bool:
        return True

    def _verify_user(self, rp_id: str) -> bool:
        return True
