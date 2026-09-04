from app.security.risk_engine import calculate_security_score


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