from app.analyzer.starttls_analyzer import analyze_starttls


def main():
    print("=" * 70)
    print("SecureMailScope - STARTTLS Analyzer Test")
    print("=" * 70)

    payloads = [
        "220 localhost SecureMailScope SMTP Lab\r\n",
        "EHLO localhost\r\n",
        "250-localhost\r\n",
        "250-STARTTLS\r\n",
        "250 SIZE 10485760\r\n",
        "STARTTLS\r\n",
        "220 2.0.0 Ready to start TLS\r\n",
    ]

    result = analyze_starttls(
        protocol="SMTP",
        payloads=payloads,
        tls_detected=True,
    )

    print("\nAnalysis Result:")
    print(f"  STARTTLS supported: {result['starttls_supported']}")
    print(f"  STARTTLS requested: {result['starttls_requested']}")
    print(f"  TLS upgrade detected: {result['tls_upgrade_detected']}")
    print(f"  Commands found: {result['commands_found']}")

    print("\nExpected:")
    print("  STARTTLS supported: True")
    print("  STARTTLS requested: True")
    print("  TLS upgrade detected: True")
    print("  Commands found: ['STARTTLS']")

    print("\n" + "=" * 70)
    print("STARTTLS analyzer testing completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()