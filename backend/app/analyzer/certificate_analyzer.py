from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    dsa,
    ed25519,
    ed448,
    padding,
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


def _certificate_validity(certificate):
    """
    Return certificate validity information using the modern
    cryptography API when available, with compatibility fallback.
    """

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

    return not_before, not_after


def _certificate_summary(certificate):
    """
    Return a compact forensic summary of an X.509 certificate.
    """

    not_before, not_after = _certificate_validity(
        certificate
    )

    public_key_info = get_public_key_info(
        certificate.public_key()
    )

    signature_algorithm = (
        certificate.signature_hash_algorithm.name
        if certificate.signature_hash_algorithm
        else "Unknown"
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

        "expired": (
            datetime.now(timezone.utc) > not_after
        ),

        "not_yet_valid": (
            datetime.now(timezone.utc) < not_before
        ),

        "public_key_algorithm": (
            public_key_info["algorithm"]
        ),

        "public_key_length": (
            public_key_info["key_size"]
        ),

        "signature_algorithm": signature_algorithm,

        "certificate_version": (
            certificate.version.name
        ),

        "fingerprint_sha256": (
            certificate.fingerprint(
                hashes.SHA256()
            ).hex()
        ),
    }


def analyze_certificate(certificate_bytes):
    """
    Analyze a single DER-encoded X.509 certificate.

    This function preserves the original SecureMailScope
    certificate-analysis output for backward compatibility.
    """

    certificate = x509.load_der_x509_certificate(
        certificate_bytes
    )

    return _certificate_summary(certificate)


def _same_name(name_a, name_b):
    """
    Compare X.509 names using their canonical RFC4514 form.
    """

    return (
        name_a.rfc4514_string()
        == name_b.rfc4514_string()
    )


def _verify_certificate_signature(
    child_certificate,
    issuer_certificate,
):
    """
    Verify that child_certificate was signed by
    issuer_certificate.

    Returns:
        True  -> signature verified
        False -> signature verification failed
    """

    public_key = issuer_certificate.public_key()

    try:

        if isinstance(
            public_key,
            rsa.RSAPublicKey,
        ):
            child_certificate.signature_hash_algorithm

            public_key.verify(
                child_certificate.signature,
                child_certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child_certificate.signature_hash_algorithm,
            )

            return True

        if isinstance(
            public_key,
            ec.EllipticCurvePublicKey,
        ):

            public_key.verify(
                child_certificate.signature,
                child_certificate.tbs_certificate_bytes,
                ec.ECDSA(
                    child_certificate.signature_hash_algorithm
                ),
            )

            return True

        if isinstance(
            public_key,
            dsa.DSAPublicKey,
        ):

            public_key.verify(
                child_certificate.signature,
                child_certificate.tbs_certificate_bytes,
                child_certificate.signature_hash_algorithm,
            )

            return True

        if isinstance(
            public_key,
            ed25519.Ed25519PublicKey,
        ):

            public_key.verify(
                child_certificate.signature,
                child_certificate.tbs_certificate_bytes,
            )

            return True

        if isinstance(
            public_key,
            ed448.Ed448PublicKey,
        ):

            public_key.verify(
                child_certificate.signature,
                child_certificate.tbs_certificate_bytes,
            )

            return True

    except Exception:
        return False

    return False


def _is_self_signed(certificate):
    """
    Determine whether a certificate is self-signed.
    """

    if not _same_name(
        certificate.subject,
        certificate.issuer,
    ):
        return False

    return _verify_certificate_signature(
        certificate,
        certificate,
    )


def _build_certificate_chain(certificates):
    """
    Build an issuer chain from certificates observed in
    the PCAP.

    The first certificate is assumed to be the leaf/server
    certificate because TLS servers normally present the
    leaf certificate first.

    Returns:
        ordered certificates
        chain links
        validation information
    """

    if not certificates:
        return {
            "certificates_observed": 0,
            "chain_complete": False,
            "chain_valid": None,
            "validation_status": "Not observed",
            "validation_message": (
                "No X.509 certificates were observed."
            ),
            "certificates": [],
            "chain_links": [],
        }

    # Remove exact duplicate certificates while preserving
    # the original order observed in the PCAP.
    unique_certificates = []

    seen_fingerprints = set()

    for certificate in certificates:

        fingerprint = certificate.fingerprint(
            hashes.SHA256()
        ).hex()

        if fingerprint in seen_fingerprints:
            continue

        seen_fingerprints.add(fingerprint)
        unique_certificates.append(certificate)

    certificates = unique_certificates

    leaf = certificates[0]

    ordered_chain = [leaf]

    remaining = certificates[1:]

    chain_links = []

    current = leaf

    while True:

        # Already at a self-signed root.
        if _is_self_signed(current):

            break

        issuer_certificate = None

        for candidate in remaining:

            if _same_name(
                current.issuer,
                candidate.subject,
            ):
                issuer_certificate = candidate
                break

        if issuer_certificate is None:
            break

        signature_valid = _verify_certificate_signature(
            current,
            issuer_certificate,
        )

        chain_links.append(
            {
                "subject": (
                    current.subject.rfc4514_string()
                ),
                "issuer": (
                    current.issuer.rfc4514_string()
                ),
                "signature_valid": signature_valid,
            }
        )

        ordered_chain.append(
            issuer_certificate
        )

        remaining.remove(
            issuer_certificate
        )

        current = issuer_certificate

    # Determine whether the observed chain reaches a
    # self-signed certificate.
    terminates_in_self_signed_root = (
        _is_self_signed(
            ordered_chain[-1]
        )
    )

    # Every observed issuer relationship must verify.
    all_links_valid = all(
        link["signature_valid"]
        for link in chain_links
    )

    # We can only call the chain complete when it
    # terminates in a self-signed certificate.
    #
    # A normal TLS server often does NOT send the root CA,
    # so leaf -> intermediate may be valid but incomplete.
    chain_complete = (
        terminates_in_self_signed_root
    )

    if not chain_links:

        if terminates_in_self_signed_root:

            chain_valid = True

            validation_status = "Valid"

            validation_message = (
                "The observed certificate is "
                "self-signed and its signature verifies."
            )

        else:

            chain_valid = None

            validation_status = "Incomplete"

            validation_message = (
                "Only the leaf certificate was observed; "
                "its issuer certificate was not captured."
            )

    elif not all_links_valid:

        chain_valid = False

        validation_status = "Invalid"

        validation_message = (
            "One or more observed certificate "
            "signatures could not be verified."
        )

    elif chain_complete:

        chain_valid = True

        validation_status = "Valid"

        validation_message = (
            "The observed certificate chain is "
            "complete and all certificate signatures verify."
        )

    else:

        chain_valid = None

        validation_status = "Incomplete"

        validation_message = (
            "The observed certificate chain is internally "
            "consistent, but the remaining issuer/root "
            "certificate was not captured in the PCAP."
        )

    chain_certificate_summaries = []

    for certificate in ordered_chain:

        summary = _certificate_summary(
            certificate
        )

        chain_certificate_summaries.append(
            {
                "subject": summary["subject"],
                "issuer": summary["issuer"],
                "serial_number": summary["serial_number"],
                "valid_from": summary["valid_from"],
                "valid_until": summary["valid_until"],
                "expired": summary["expired"],
                "not_yet_valid": summary["not_yet_valid"],
                "public_key_algorithm": (
                    summary["public_key_algorithm"]
                ),
                "public_key_length": (
                    summary["public_key_length"]
                ),
                "signature_algorithm": (
                    summary["signature_algorithm"]
                ),
                "fingerprint_sha256": (
                    summary["fingerprint_sha256"]
                ),
                "self_signed": _is_self_signed(
                    certificate
                ),
            }
        )

    return {
        "certificates_observed": len(certificates),

        "chain_complete": chain_complete,

        "chain_valid": chain_valid,

        "validation_status": validation_status,

        "validation_message": validation_message,

        "certificates": chain_certificate_summaries,

        "chain_links": chain_links,
    }


def analyze_certificate_chain(
    certificate_bytes_list,
):
    """
    Analyze all DER-encoded X.509 certificates observed
    in a TLS handshake.

    The first certificate is treated as the leaf/server
    certificate, matching normal TLS certificate ordering.
    """

    if not certificate_bytes_list:

        return {
            "certificate_present": False,
            "certificate_count": 0,
            "certificate_status": "not_observed",
        }

    certificates = []

    for certificate_bytes in certificate_bytes_list:

        try:

            certificate = (
                x509.load_der_x509_certificate(
                    certificate_bytes
                )
            )

            certificates.append(
                certificate
            )

        except Exception:
            # Ignore malformed individual certificates
            # while preserving certificates that can be
            # parsed successfully.
            continue

    return _build_certificate_chain(
        certificates
    )