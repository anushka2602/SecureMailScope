from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    dsa,
    ed25519,
    ed448,
)


def get_public_key_info(public_key):

    if isinstance(public_key, rsa.RSAPublicKey):
        return {
            "algorithm": "RSA",
            "key_size": public_key.key_size,
        }

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "algorithm": "EC",
            "key_size": public_key.key_size,
        }

    if isinstance(public_key, dsa.DSAPublicKey):
        return {
            "algorithm": "DSA",
            "key_size": public_key.key_size,
        }

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return {
            "algorithm": "Ed25519",
            "key_size": None,
        }

    if isinstance(public_key, ed448.Ed448PublicKey):
        return {
            "algorithm": "Ed448",
            "key_size": None,
        }

    return {
        "algorithm": type(public_key).__name__,
        "key_size": None,
    }


def analyze_certificate(certificate_bytes):

    certificate = x509.load_der_x509_certificate(
        certificate_bytes
    )

    now = datetime.now(timezone.utc)

    try:
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
    except AttributeError:

        not_before = (
            certificate.not_valid_before
            .replace(tzinfo=timezone.utc)
        )

        not_after = (
            certificate.not_valid_after
            .replace(tzinfo=timezone.utc)
        )

    public_key_info = get_public_key_info(
        certificate.public_key()
    )

    return {
        "certificate_present": True,

        "subject": (
            certificate.subject.rfc4514_string()
        ),

        "issuer": (
            certificate.issuer.rfc4514_string()
        ),

        "serial_number": str(
            certificate.serial_number
        ),

        "valid_from": not_before.isoformat(),

        "valid_until": not_after.isoformat(),

        "expired": now > not_after,

        "not_yet_valid": now < not_before,

        "public_key_algorithm": (
            public_key_info["algorithm"]
        ),

        "public_key_length": (
            public_key_info["key_size"]
        ),

        "signature_algorithm": (
            certificate.signature_hash_algorithm.name
            if certificate.signature_hash_algorithm
            else "Unknown"
        ),

        "certificate_version": (
            certificate.version.name
        ),

        "fingerprint_sha256": (
            certificate.fingerprint(
                hashes.SHA256()
            ).hex()
        ),
    }