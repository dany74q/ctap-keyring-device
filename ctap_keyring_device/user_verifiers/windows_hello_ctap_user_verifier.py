# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
import winrt.windows.security.credentials.ui as ui
import asyncio

from ctap_keyring_device.user_verifiers.ctap_user_verifier import CtapUserVerifierBase


class WindowsHelloCtapUserVerifier(CtapUserVerifierBase):
    """ A Windows Hello based CTAP User verifier; Prompts for a PIN / fingerprint """

    def __init__(self):
        self._event_loop = asyncio.get_event_loop()

    def _available(self) -> bool:
        fut = ui.UserConsentVerifier.check_availability_async()
        res = self._event_loop.run_until_complete(fut)

        return res == ui.UserConsentVerifierAvailability.AVAILABLE

    def _verify_user(self, rp_id: str) -> bool:
        fut = ui.UserConsentVerifier.request_verification_async(
            'verify ctap user identity of ' + rp_id
        )
        res = self._event_loop.run_until_complete(fut)

        return res == ui.UserConsentVerificationResult.VERIFIED
