import re
from datetime import datetime, timedelta
from functools import partial
from importlib.abc import Traversable
from logging import getLogger
from typing import Callable, Type, TypeVar, overload

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509 import Certificate, CertificateSigningRequest, load_pem_x509_certificate, load_pem_x509_csr

T = TypeVar("T")

logger = getLogger(__name__)


def _read_with_transform(path: Traversable, transform: Callable[[bytes], T]) -> T | None:
    if path.is_file() is False:
        return None

    with path.open("rb") as f:
        try:
            result = transform(f.read())
            if result is None:
                return None
        except ValueError as e:
            logger.error(f"Failed to read file or credential: {path.name}", exc_info=e)
            return None

        logger.debug(f"Reading already existing file or credential: {path.name}")
        return result


@overload
def create_private_key(
    path: Traversable,
    key_type: Type[ec.EllipticCurvePrivateKey],
    key_size: int = 2048,
) -> ec.EllipticCurvePrivateKey:
    ...


@overload
def create_private_key(
    path: Traversable,
    key_type: Type[rsa.RSAPrivateKey] = rsa.RSAPrivateKey,
    key_size: int = 2048,
) -> rsa.RSAPrivateKey:
    ...


def create_private_key(
    path: Traversable,
    key_type: Type[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] = rsa.RSAPrivateKey,
    key_size: int = 2048,
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    match key_type:
        case rsa.RSAPrivateKey:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        case ec.EllipticCurvePrivateKey:
            private_key = ec.generate_private_key(ec.SECP256R1())
        case _:
            raise TypeError(f"Unknown key type {key_type}")

    with path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption(),
            ),
        )

    return private_key


@overload
def read_private_key(
    path: Traversable,
    key_type: Type[ec.EllipticCurvePrivateKey],
) -> ec.EllipticCurvePrivateKey | None:
    ...


@overload
def read_private_key(
    path: Traversable,
    key_type: Type[rsa.RSAPrivateKey] = rsa.RSAPrivateKey,
) -> rsa.RSAPrivateKey | None:
    ...


def read_private_key(
    path: Traversable,
    key_type: Type[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] = rsa.RSAPrivateKey,
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None:
    assert key_type in (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)
    return _read_with_transform(path, partial(load_pem_private_key, password=None))


@overload
def create_public_key(path: Traversable, private_key: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePublicKey:
    ...


@overload
def create_public_key(path: Traversable, private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    ...


def create_public_key(
    path: Traversable,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    public_key = private_key.public_key()

    with path.open("wb") as f:
        f.write(public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))

    return public_key


@overload
def read_public_key(path: Traversable, key_type: Type[ec.EllipticCurvePublicKey]) -> ec.EllipticCurvePublicKey | None:
    ...


@overload
def read_public_key(path: Traversable, key_type: Type[rsa.RSAPublicKey] = rsa.RSAPublicKey) -> rsa.RSAPublicKey | None:
    ...


def read_public_key(
    path: Traversable,
    key_type: Type[rsa.RSAPublicKey | ec.EllipticCurvePublicKey] = rsa.RSAPublicKey,
) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | None:
    assert key_type in (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
    return _read_with_transform(path, partial(load_pem_public_key))


def save_public_key(path: Traversable, private_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
    with path.open("wb") as f:
        f.write(private_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))


def save_certificate(path: Traversable, certificate: Certificate):
    with path.open("wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))


def read_certificate(path: Traversable) -> Certificate | None:
    certificate = _read_with_transform(path, load_pem_x509_certificate)

    if certificate is None or certificate.not_valid_after < datetime.now() - timedelta(days=1):
        return None

    return certificate


def save_csr(path: Traversable, csr: CertificateSigningRequest):
    with path.open("wb") as f:
        f.write(csr.public_bytes(Encoding.PEM))


def read_csr(path: Traversable) -> CertificateSigningRequest | None:
    return _read_with_transform(path, load_pem_x509_csr)


def strip_pem(pem: Certificate | RSAPrivateKey | bytes | str, remove_newline=True) -> bytes:
    if isinstance(pem, RSAPrivateKey):
        pem_str = pem.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    elif isinstance(pem, Certificate):
        pem_str = pem.public_bytes(Encoding.PEM)
    elif isinstance(pem, bytes):
        pem_str = pem
    elif isinstance(pem, str):
        pem_str = pem.encode()
    else:
        raise TypeError(f"Expected PEM, got {type(pem)}")

    result = re.sub(r"""-----(BEGIN|END) ([A-Z]+ ?)+-----""", "", pem_str.decode()).strip().encode()
    if remove_newline is True:
        result = result.replace(b"\n", b"")
    return result
