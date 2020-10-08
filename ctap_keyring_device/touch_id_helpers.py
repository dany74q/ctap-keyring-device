# -*- coding: utf-8 -*-
# @Author   :   lukaskollmer
# Taken from and slightly modified:
# https://raw.githubusercontent.com/lukaskollmer/python-touch-id/master/touchid.py (MIT License)

# noinspection PyUnresolvedReferences
from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthentication
from threading import Event


class TouchId:
    LA_POLICY = LAPolicyDeviceOwnerAuthentication

    def __init__(self):
        self._context = LAContext.new()

    def available(self) -> bool:
        return self._context.canEvaluatePolicy_error_(self.LA_POLICY, None)[0]

    def verify(self, reason) -> bool:
        if not self.available():
            raise Exception("Touch ID isn't available on this machine")

        success, err, event = False, None, Event()

        def cb(_success, _error):
            nonlocal success, err
            success = _success
            if _error:
                err = _error.localizedDescription()

            event.set()

        self._context.evaluatePolicy_localizedReason_reply_(self.LA_POLICY, reason, cb)

        event.wait()
        if err:
            raise RuntimeError(err)

        return success
