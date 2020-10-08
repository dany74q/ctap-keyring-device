# -*- coding: utf-8 -*-
# @Author   :   lukaskollmer
# Taken from and slightly modified:
# https://raw.githubusercontent.com/lukaskollmer/python-touch-id/master/touchid.py (MIT License)

from threading import Event

# noinspection PyUnresolvedReferences
from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthentication

from ctap_keyring_device.user_verifiers.ctap_user_verifier import CtapUserVerifierBase


class TouchIdCtapUserVerifier(CtapUserVerifierBase):
    """ A Touch ID based CTAP User Verifier - Prompts for the user's login password / fingerprint """

    LA_POLICY = LAPolicyDeviceOwnerAuthentication

    def __init__(self):
        self._context = LAContext.new()

    def _available(self) -> bool:
        return self._context.canEvaluatePolicy_error_(self.LA_POLICY, None)[0]

    def _verify_user(self, rp_id: str) -> bool:
        success, err, event = False, None, Event()

        def cb(_success, _error):
            nonlocal success, err
            success = _success
            if _error:
                err = _error.localizedDescription()

            event.set()

        self._context.evaluatePolicy_localizedReason_reply_(
            self.LA_POLICY, 'verify ctap user identity of ' + rp_id, cb
        )

        event.wait()
        return err is None and success
