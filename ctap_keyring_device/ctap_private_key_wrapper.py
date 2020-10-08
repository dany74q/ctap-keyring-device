# -*- coding: utf-8 -*-
import abc
from typing import Optional, Union, Type, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fido2 import cose


class CtapPrivateKeyWrapper(metaclass=abc.ABCMeta):
    """
    A private key wrapper for different COSE algorithms.

    It adds signing capabilities with all parameters pre-configured, as needed by the algorithm.
    """

    @abc.abstractmethod
    def get_key(self):
        """ Returns the wrapped private key """
        raise NotImplementedError()

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        """ Signs the given data according to the algorithm """
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_algorithm(cls) -> int:
        """ One of COSE defined algorithms, see https://www.iana.org/assignments/cose/cose.xhtml """
        raise NotImplementedError()

    def get_public_key(self):
        return self.get_key().public_key()

    @staticmethod
    def create(
        cose_key_cls: Type[cose.CoseKey],
        key: Optional[
            Union[EllipticCurvePrivateKey, rsa.RSAPrivateKey, Ed25519PrivateKey]
        ] = None,
    ):
        """
        Factory for creating a wrapper for the given cose_key_cls.

        If a key is supplied, it is wrapped, else - one is generated.
        """
        cose_key_class_to_signer: Dict[Type[cose.CoseKey]] = {
            cose.ES256: CtapEs256PrivateKeyWrapper,
            cose.RS1: CtapRs1PrivateKeyWrapper,
            cose.RS256: CtapRs256KeyGeneratorSigner,
            cose.PS256: CtapPs256PrivateKeyWrapper,
            cose.EdDSA: CtapEdDsaPrivateKeyWrapper,
        }

        signer_cls = cose_key_class_to_signer.get(cose_key_cls)
        if not signer_cls:
            raise RuntimeError('Unexpected cose key class: {}'.format(cose_key_cls))

        return signer_cls(key)


class CtapEs256PrivateKeyWrapper(CtapPrivateKeyWrapper):
    """ ES256 (ECDSA w/ SHA-256) """

    def __init__(self, key: ec.EllipticCurvePrivateKey = None):
        self._key = key or ec.generate_private_key(curve=ec.SECP256R1())

    @classmethod
    def get_algorithm(cls) -> int:
        return cose.ES256.ALGORITHM

    def get_key(self) -> EllipticCurvePrivateKey:
        return self._key

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data, signature_algorithm=ec.ECDSA(hashes.SHA256()))


class CtapRsaPrivateKeyWrapper(CtapPrivateKeyWrapper, metaclass=abc.ABCMeta):
    def __init__(self, key: rsa.RSAPrivateKey = None):
        self._key = key or rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

    def get_key(self):
        return self._key


class CtapRs256KeyGeneratorSigner(CtapRsaPrivateKeyWrapper):
    """ RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256) """

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    @classmethod
    def get_algorithm(cls) -> int:
        return cose.RS256.ALGORITHM


class CtapRs1PrivateKeyWrapper(CtapRsaPrivateKeyWrapper):
    """ RS1 (RSASSA-PKCS1-v1_5 w/ SHA-1) """

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data, padding.PKCS1v15(), hashes.SHA1())

    @classmethod
    def get_algorithm(cls) -> int:
        return cose.RS1.ALGORITHM


class CtapPs256PrivateKeyWrapper(CtapRsaPrivateKeyWrapper):
    """ PS256 (RSASSA-PSS w/ SHA-256) """

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

    @classmethod
    def get_algorithm(cls) -> int:
        return cose.PS256.ALGORITHM


class CtapEdDsaPrivateKeyWrapper(CtapPrivateKeyWrapper):
    """ EDDSA (Edwards-Curve DSA) """

    def __init__(self, key: Ed25519PrivateKey = None):
        self._key = key or ed25519.Ed25519PrivateKey.generate()

    def get_key(self):
        return self._key

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    @classmethod
    def get_algorithm(cls) -> int:
        return cose.EdDSA.ALGORITHM
