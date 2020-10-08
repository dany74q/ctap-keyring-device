# -*- coding: utf-8 -*-
# @Author   :   lukaskollmer
# Taken from and slightly modified:
# https://raw.githubusercontent.com/lukaskollmer/python-touch-id/master/touchid.py (MIT License)

# noinspection PyUnresolvedReferences
from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthentication
from threading import Event


def touch_id_available():
    context = LAContext.new()
    return context.canEvaluatePolicy_error_(LAPolicyDeviceOwnerAuthentication, None)[0]


def touch_id_verify(reason):
    context = LAContext.new()

    can_evaluate = context.canEvaluatePolicy_error_(
        LAPolicyDeviceOwnerAuthentication, None
    )[0]
    if not can_evaluate:
        raise Exception("Touch ID isn't available on this machine")

    success, err, event = False, None, Event()

    def cb(_success, _error):
        nonlocal success, err
        success = _success
        if _error:
            err = _error.localizedDescription()

        event.set()

    context.evaluatePolicy_localizedReason_reply_(
        LAPolicyDeviceOwnerAuthentication, reason, cb
    )

    event.wait()
    if err:
        raise RuntimeError(err)

    return success
