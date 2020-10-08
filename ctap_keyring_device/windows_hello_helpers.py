# -*- coding: utf-8 -*-
# @Time     :   6/24/2019 9:03 PM
# @Author   :   Luspock
# Taken from and slightly modified:
# https://raw.githubusercontent.com/luspock/FingerPrint/master/fingerprint.py (MIT License)


import ctypes
from ctypes import wintypes

SECURITY_MAX_SID_SIZE = 68
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 0x00000001
WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_ID_TYPE_SID = 3
WINBIO_E_NO_MATCH = 0x80098005
WINBIO_FINGER_UNSPECIFIED_POS_01 = ctypes.c_ubyte(0xF5)

winbio = ctypes.WinDLL(r"C:\Windows\System32\winbio.dll")


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class AccountSid(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.ULONG),
        ("Data", ctypes.c_ubyte * SECURITY_MAX_SID_SIZE),
    ]


class Value(ctypes.Union):
    _fields_ = [
        ("NULL", wintypes.ULONG),
        ("Wildcard", wintypes.ULONG),
        ("TemplateGuid", GUID),
        ("AccountSid", AccountSid),
    ]


# noinspection PyPep8Naming
class WINBIO_IDENTITY(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_uint32), ("Value", Value)]


# noinspection PyPep8Naming
class TOKEN_INFORMATION_CLASS:
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3


# noinspection PyPep8Naming
class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", wintypes.BYTE * 6)]


# https://www.csie.ntu.edu.tw/~r92094/c++/Win_Header/WINNT.H
class SID(ctypes.Structure):
    _fields_ = [
        ("Revision", wintypes.BYTE),
        ("SubAuthorityCount", wintypes.BYTE),
        ("IdentifierAuthority", SID_IDENTIFIER_AUTHORITY),
        ("SubAuthority", wintypes.DWORD),
    ]


# noinspection PyPep8Naming
class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.POINTER(SID)), ("Attributes", wintypes.DWORD)]


# noinspection PyPep8Naming
class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


# noinspection PyPep8Naming
class WindowsHello:
    def __init__(self):
        self.session_handle = ctypes.c_uint32()
        self.unit_id = ctypes.c_uint32()

        # full definition is in winbio_types.h
        self.subfactor = WINBIO_FINGER_UNSPECIFIED_POS_01

        # WINBIO_ID_TYPE_SID = 3
        self.identity = WINBIO_IDENTITY()
        self.is_open = False

    def __enter__(self):
        self.open()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @classmethod
    def available(cls):
        if winbio is None:
            return False

        enabled = wintypes.BOOLEAN()
        source = wintypes.ULONG()
        res = winbio.WinBioGetEnabledSetting(
            ctypes.byref(enabled), ctypes.byref(source)
        )
        return res == 0 and enabled

    def open(self):
        if self.is_open:
            return

        res = winbio.WinBioOpenSession(
            WINBIO_TYPE_FINGERPRINT,
            WINBIO_POOL_SYSTEM,
            WINBIO_FLAG_DEFAULT,
            None,
            0,
            None,
            ctypes.byref(self.session_handle),
        )  # pool   system
        if res != 0:
            return False

        self.is_open = True
        return True

    def locate_unit(self):
        res = winbio.WinBioLocateSensor(self.session_handle, ctypes.byref(self.unit_id))
        return res == 0

    def identify(self):
        reject_detail = ctypes.c_uint32()
        res = winbio.WinBioIdentify(
            self.session_handle,
            ctypes.byref(self.unit_id),
            ctypes.byref(self.identity),
            ctypes.byref(self.subfactor),
            ctypes.byref(reject_detail),
        )
        if res != 0:
            raise Exception("Identify Error")

    def verify(self):
        match = ctypes.c_bool(False)
        reject_detail = ctypes.c_uint32()
        # get identity
        self.get_current_user_identity()
        res = winbio.WinBioVerify(
            self.session_handle,
            ctypes.byref(self.identity),
            self.subfactor,
            ctypes.byref(self.subfactor),
            ctypes.byref(match),
            ctypes.byref(reject_detail),
        )
        if res == 0 or (res & 0xFFFFFFFF) == WINBIO_E_NO_MATCH:
            return match.value
        else:
            raise Exception("Identify Error")

    def close(self):
        if not self.is_open:
            return

        winbio.WinBioCloseSession(self.session_handle)
        self.session_handle = 0
        self.is_open = False

    def get_current_user_identity(self):
        self.get_token_information()

    @staticmethod
    def get_process_token():
        """
        Get the current process token
        """
        #  Reference
        #  https://gist.github.com/schlamar/7024668
        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.restype = wintypes.HANDLE
        OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
        OpenProcessToken.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        )
        OpenProcessToken.restype = wintypes.BOOL
        token = wintypes.HANDLE()

        # https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h
        # TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY = 0x00020000 | 0x0008 = 0x20008
        TOKEN_READ = 0x20008
        res = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, token)
        if not res > 0:
            raise RuntimeError("Couldn't get process token")

        return token

    def get_token_information(self):
        """
        Get token info associated with the current process.
        """
        GetTokenInformation = ctypes.windll.advapi32.GetTokenInformation
        GetTokenInformation.argtypes = [
            wintypes.HANDLE,  # TokenHandle
            ctypes.c_uint,  # TOKEN_INFORMATION_CLASS value
            wintypes.LPVOID,  # TokenInformation
            wintypes.DWORD,  # TokenInformationLength
            ctypes.POINTER(wintypes.DWORD),  # ReturnLength
        ]
        GetTokenInformation.restype = wintypes.BOOL

        CopySid = ctypes.windll.advapi32.CopySid
        CopySid.argtypes = [
            wintypes.DWORD,  # nDestinationSidLength
            ctypes.c_void_p,  # pDestinationSid,
            ctypes.c_void_p,  # pSourceSid
        ]
        CopySid.restype = wintypes.BOOL

        GetLengthSid = ctypes.windll.advapi32.GetLengthSid
        GetLengthSid.argtypes = [ctypes.POINTER(SID)]  # PSID
        GetLengthSid.restype = wintypes.DWORD

        return_length = wintypes.DWORD(0)
        buffer = ctypes.create_string_buffer(SECURITY_MAX_SID_SIZE)

        res = GetTokenInformation(
            self.get_process_token(),
            TOKEN_INFORMATION_CLASS.TokenUser,
            buffer,
            SECURITY_MAX_SID_SIZE,
            ctypes.byref(return_length),
        )
        assert res > 0, "Error in second GetTokenInformation (%d)" % res

        token_user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        CopySid(
            SECURITY_MAX_SID_SIZE,
            self.identity.Value.AccountSid.Data,
            token_user.User.Sid,
        )
        self.identity.Type = WINBIO_ID_TYPE_SID
        self.identity.Value.AccountSid.Size = GetLengthSid(token_user.User.Sid)
