# -*- coding: utf-8 -*-
import platform

from ctap_keyring_device.user_verifiers.ctap_user_verifier import CtapUserVerifier
from ctap_keyring_device.user_verifiers.noop_ctap_user_verifier import (
    NoopCtapUserVerifier,
)

try:
    from ctap_keyring_device.user_verifiers.touch_id_ctap_user_verifier import (
        TouchIdCtapUserVerifier,
    )
except ImportError:
    TouchIdCtapUserVerifier = None

try:
    from ctap_keyring_device.user_verifiers.windows_hello_ctap_user_verifier import (
        WindowsHelloCtapUserVerifier,
    )
except ImportError:
    WindowsHelloCtapUserVerifier = None


class CtapUserVerifierFactory:
    """Creates a concrete instance of a CtapUserVerifier implementation, depending on the platform and available
    user presence detection mechanisms available"""

    @staticmethod
    def create() -> CtapUserVerifier:
        system = platform.system()
        if system == 'Darwin' and TouchIdCtapUserVerifier is not None:
            touch_id_verifier = TouchIdCtapUserVerifier()
            if touch_id_verifier.available():
                return touch_id_verifier

        if system == 'Windows' and WindowsHelloCtapUserVerifier is not None:
            windows_hello_verifier = WindowsHelloCtapUserVerifier()
            if windows_hello_verifier.available():
                return windows_hello_verifier

        return NoopCtapUserVerifier()
