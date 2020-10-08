# -*- coding: utf-8 -*-
import abc

# noinspection PyBroadException
try:
    from ctap_keyring_device.user_verifiers.windows_hello_ctap_user_verifier import (
        WindowsHelloCtapUserVerifier,
    )
except Exception:
    WindowsHelloCtapUserVerifier = None

# noinspection PyBroadException
try:
    from ctap_keyring_device.user_verifiers.touch_id_ctap_user_verifier import (
        TouchIdCtapUserVerifier,
    )
except Exception:
    TouchIdCtapUserVerifier = None


class CtapUserVerifier(metaclass=abc.ABCMeta):
    """
    Implementors of this interface supply a user verification and presence scheme.

    This could be with biometrics, face-recognition, password prompt, or otherwise.
    """

    @abc.abstractmethod
    def available(self) -> bool:
        """ If set, this verifier is available on the current OS """
        raise NotImplementedError()

    @abc.abstractmethod
    def verify_user(self, rp_id: str) -> bool:
        """ Returns true if the user was successfully verified """
        raise NotImplementedError()


class CtapUserVerifierBase(CtapUserVerifier, metaclass=abc.ABCMeta):
    """A base class for user verifiers - implemented methods may throw, in which case False is returned
    in both available() and verify_user()"""

    def available(self) -> bool:
        # noinspection PyBroadException
        try:
            return self._available()
        except Exception:
            return False

    @abc.abstractmethod
    def _available(self) -> bool:
        raise NotImplementedError()

    def verify_user(self, rp_id: str) -> bool:
        if not self.available():
            return False

        # noinspection PyBroadException
        try:
            return self._verify_user(rp_id)
        except Exception:
            return False

    @abc.abstractmethod
    def _verify_user(self, rp_id: str) -> bool:
        raise NotImplementedError()
