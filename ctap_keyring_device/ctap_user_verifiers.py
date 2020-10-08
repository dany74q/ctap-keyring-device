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
    from ctap_keyring_device.touch_id_helpers import touch_id_verify, touch_id_available
except Exception:
    touch_id_verify, touch_id_available = None, None


class CtapUserVerifier(metaclass=abc.ABCMeta):
    """
    Implementors of this interface supply a user verification and presence scheme.

    This could be with biometrics, face-recognition, password prompt, or otherwise.
    """

    @classmethod
    @abc.abstractmethod
    def available(cls) -> bool:
        """ If set, this verifier is available on the current OS """
        raise NotImplementedError()

    @abc.abstractmethod
    def verify_user(self, rp_id: str) -> bool:
        """ Returns true if the user was successfully verified """
        raise NotImplementedError()

    @staticmethod
    def create():
        system = platform.system()
        if system == 'Darwin' and TouchIdCtapUserVerifier.available():
            return TouchIdCtapUserVerifier()

        if system == 'Windows' and WindowsHelloCtapUserVerifier.available():
            return WindowsHelloCtapUserVerifier()

        return NoopCtapUserVerifier()


class NoopCtapUserVerifier(CtapUserVerifier):
    """ Dummy verifier - always returns true """

    @classmethod
    def available(cls) -> bool:
        return True

    def verify_user(self, rp_id: str) -> bool:
        return True


class TouchIdCtapUserVerifier(CtapUserVerifier):
    """ OSX Touch-ID based user verifier, prompts for a touch id / password """

    @classmethod
    def available(cls) -> bool:
        return touch_id_available is not None and touch_id_available()

    def verify_user(self, rp_id: str) -> bool:
        # noinspection PyBroadException
        try:
            return touch_id_verify('verify ctap user identity of ' + rp_id)
        except Exception:
            return False


class WindowsHelloCtapUserVerifier(CtapUserVerifier):
    """ Windows Hello based user verifier, prompts for a biometric / pin """

    @classmethod
    def available(cls) -> bool:
        return WindowsHello is not None

    def verify_user(self, rp_id: str) -> bool:
        # noinspection PyBroadException
        try:
            with WindowsHello() as wh:
                return wh.verify()
        except Exception:
            return False
