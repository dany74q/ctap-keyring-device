# -*- coding: utf-8 -*-
import abc
import platform

# noinspection PyBroadException
try:
    from ctap_keyring_device.windows_hello_helpers import WindowsHello
except Exception:
    WindowsHello = None

# noinspection PyBroadException
try:
    from ctap_keyring_device.touch_id_helpers import TouchId
except Exception:
    TouchId = None


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

    @staticmethod
    def create():
        system = platform.system()
        if system == 'Darwin':
            touch_id_verifier = TouchIdCtapUserVerifier()
            if touch_id_verifier.available():
                return touch_id_verifier

        if system == 'Windows':
            windows_hello_verifier = WindowsHelloCtapUserVerifier()
            if windows_hello_verifier.available():
                return windows_hello_verifier

        return NoopCtapUserVerifier()


class NoopCtapUserVerifier(CtapUserVerifier):
    """ Dummy verifier - always returns true """

    def available(self) -> bool:
        return True

    def verify_user(self, rp_id: str) -> bool:
        return True


class TouchIdCtapUserVerifier(CtapUserVerifier):
    """ OSX Touch-ID based user verifier, prompts for a touch id / password """

    def __init__(self):
        self._touch_id = TouchId() if TouchId else None

    def available(self) -> bool:
        return self._touch_id is not None and self._touch_id.available()

    def verify_user(self, rp_id: str) -> bool:
        if self._touch_id is None:
            return False

        # noinspection PyBroadException
        try:
            return self._touch_id.verify('verify ctap user identity of ' + rp_id)
        except Exception:
            return False


class WindowsHelloCtapUserVerifier(CtapUserVerifier):
    """ Windows Hello based user verifier, prompts for a biometric / pin """

    def __init__(self):
        self._wh = WindowsHello() if WindowsHello else None

    def available(self) -> bool:
        return self._wh is not None and self._wh.available() and self._wh.open()

    def verify_user(self, rp_id: str) -> bool:
        if self._wh is None:
            return False

        # noinspection PyBroadException
        try:
            with self._wh as wh:
                return wh.verify()
        except Exception:
            return False
