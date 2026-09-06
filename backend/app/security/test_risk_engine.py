import pytest

from app.security.risk_engine import calculate_security_score


@pytest.mark.parametrize(
    ("data", "message", "score", "severity"),
    [
        (
            {"tls_version": "TLS1.0", "tls_detected": True},
            "Deprecated TLS 1.0 is in use.",
            35,
            "Medium",
        ),
        (
            {"tls_version": "TLS1.1", "tls_detected": True},
            "Deprecated TLS 1.1 is in use.",
            25,
            "Low",
        ),
        (
            {"tls_version": "TLS1.3", "tls_detected": True, "cipher": "3DES"},
            "3DES is a weak/deprecated cipher.",
            30,
            "Medium",
        ),
        (
            {
                "tls_version": "TLS1.3",
                "tls_detected": True,
                "key_exchange": "RSA",
            },
            "RSA key exchange is in use and does not provide forward secrecy.",
            15,
            "Low",
        ),
        (
            {
                "tls_version": "TLS1.3",
                "tls_detected": True,
                "key_size": 1024,
                "public_key_algorithm": "RSA",
            },
            "Weak public key size detected: 1024 bits.",
            25,
            "Low",
        ),
        (
            {"tls_version": "TLS1.3", "tls_detected": True, "cert_expired": True},
            "TLS certificate is expired.",
            30,
            "Medium",
        ),
        (
            {
                "tls_version": "TLS1.3",
                "tls_detected": True,
                "signature_algorithm": "SHA-1",
            },
            "SHA-1 certificate signature detected.",
            25,
            "Low",
        ),
        (
            {"tls_version": None, "tls_detected": False},
            "No TLS protection was observed for this email session.",
            30,
            "Medium",
        ),
    ],
)
def test_bad_security_conditions_are_weaknesses(
    data,
    message,
    score,
    severity,
):
    result = calculate_security_score(data)

    assert result["security_score"] == score
    assert result["severity"] == severity
    assert {"type": "weakness", "message": message} in result["findings"]


def test_unknown_tls_version_is_a_visibility_limitation():
    result = calculate_security_score(
        {
            "tls_version": None,
            "tls_detected": True,
            "cipher": None,
        }
    )

    assert result["security_score"] == 0
    assert result["severity"] == "Low"
    assert result["findings"] == [
        {
            "type": "visibility",
            "message": "TLS traffic was observed, but the negotiated TLS version could not be determined.",
        }
    ]


def test_starttls_support_without_request_does_not_trigger_upgrade_finding():
    result = calculate_security_score(
        {
            "tls_detected": False,
            "starttls": 1,
            "starttls_supported": True,
            "starttls_requested": False,
        }
    )

    assert result["security_score"] == 30
    assert not any(
        finding["message"]
        == "STARTTLS was requested, but no TLS traffic was observed after the upgrade request."
        for finding in result["findings"]
    )


def test_starttls_request_without_tls_triggers_upgrade_finding():
    result = calculate_security_score(
        {
            "tls_detected": False,
            "starttls_requested": True,
        }
    )

    assert result["security_score"] == 50
    assert {
        "type": "weakness",
        "message": "STARTTLS was requested, but no TLS traffic was observed after the upgrade request.",
    } in result["findings"]


test_cases = [
    {
        "name": "Secure SMTP",
        "protocol": "SMTP",
        "tls_version": "TLS1.3",
        "cipher": "AES_256_GCM",
        "key_size": None,
        "cert_expired": None,
        "cert_not_yet_valid": None,
        "signature_algorithm": None,
        "starttls": 1,
        "forward_secrecy": 1,
        "direct_tls": 0,
    },
    {
        "name": "Secure Direct TLS",
        "protocol": "IMAPS",
        "tls_version": "TLS1.3",
        "cipher": "AES_256_GCM",
        "key_size": None,
        "cert_expired": None,
        "cert_not_yet_valid": None,
        "signature_algorithm": None,
        "starttls": 0,
        "forward_secrecy": 1,
        "direct_tls": 1,
    },
    {
        "name": "Legacy TLS",
        "protocol": "SMTP",
        "tls_version": "TLS1.0",
        "cipher": "3DES",
        "key_size": 1024,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA1",
        "starttls": 1,
        "forward_secrecy": 0,
        "direct_tls": 0,
    },
    {
        "name": "Expired Certificate",
        "protocol": "IMAP",
        "tls_version": "TLS1.2",
        "cipher": "AES_256_GCM",
        "key_size": 2048,
        "cert_expired": 1,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA256",
        "starttls": 1,
        "forward_secrecy": 1,
        "direct_tls": 0,
    },
    {
        "name": "No STARTTLS",
        "protocol": "SMTP",
        "tls_version": "TLS1.2",
        "cipher": "AES_256_GCM",
        "key_size": 2048,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA256",
        "starttls": 0,
        "forward_secrecy": 1,
        "direct_tls": 0,
    },
]


def main():

    print("=" * 70)
    print("SecureMailScope - Security Risk Engine")
    print("=" * 70)

    for test_case in test_cases:

        name = test_case["name"]

        data = {
            key: value
            for key, value in test_case.items()
            if key != "name"
        }

        result = calculate_security_score(data)

        print("\n" + "-" * 70)
        print(f"TEST CASE: {name}")
        print("-" * 70)

        print(
            f"Security Score: "
            f"{result['security_score']}/100"
        )

        print(
            f"Severity: "
            f"{result['severity']}"
        )

        print("\nFindings:")

        if result["findings"]:

            for finding in result["findings"]:
                print(f"  • {finding}")

        else:
            print("  None")

        print("\nRecommendations:")

        if result["recommendations"]:

            for recommendation in result["recommendations"]:
                print(f"  • {recommendation}")

        else:
            print("  None")

    print("\n" + "=" * 70)
    print("Risk engine testing completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
