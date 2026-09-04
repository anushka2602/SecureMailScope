from app.security.security_posture import analyze_security_posture


test_cases = [
    {
        "name": "Secure SMTP",
        "protocol": "SMTP",
        "tls_version": "TLS1.3",
        "cipher": "AES_256_GCM",
        "key_size": 2048,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA256",
        "starttls": 1,
        "forward_secrecy": 1,
    },
    {
        "name": "Legacy TLS Attack Surface",
        "protocol": "SMTP",
        "tls_version": "TLS1.0",
        "cipher": "3DES",
        "key_size": 1024,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA1",
        "starttls": 1,
        "forward_secrecy": 0,
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
    },
]


def main():

    print("=" * 80)
    print("SecureMailScope - Unified Security Posture Test")
    print("=" * 80)

    for test_case in test_cases:

        name = test_case["name"]

        data = {
            key: value
            for key, value in test_case.items()
            if key != "name"
        }

        result = analyze_security_posture(data)

        print("\n" + "-" * 80)
        print(f"TEST CASE: {name}")
        print("-" * 80)

        print(f"Protocol: {result['protocol']}")

        print("\nML Risk Classification:")
        print(f"  Label: {result['risk']['label']}")
        print(f"  Confidence: {result['risk']['confidence']}")
        print(f"  Probabilities: {result['risk']['probabilities']}")

        print("\nAnomaly Detection:")
        print(f"  Anomaly: {result['anomaly']['is_anomaly']}")
        print(f"  Anomaly Score: {result['anomaly']['anomaly_score']}")

        print("\nRule-Based Security Assessment:")
        print(f"  Score: {result['security']['score']}/100")
        print(f"  Severity: {result['security']['severity']}")

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

    print("\n" + "=" * 80)
    print("Unified security posture testing completed.")
    print("=" * 80)


if __name__ == "__main__":
    main()