EMAIL_PROTOCOLS = {
    "smtp": "SMTP",
    "smtp_tls": "SMTP over TLS",
    "imap": "IMAP",
    "imap_tls": "IMAP over TLS",
    "pop": "POP3",
    "pop_tls": "POP3 over TLS",
}


def detect_protocols(packets):
    """
    Detect protocols present in a TShark packet JSON result.
    """

    protocols = set()

    for packet in packets:
        layers = (
            packet
            .get("_source", {})
            .get("layers", {})
        )

        for protocol in layers.keys():
            protocols.add(protocol)

    return sorted(protocols)


def detect_email_protocols(packets):
    """
    Detect email-related protocols from TShark packet layers.
    """

    detected = set()

    for packet in packets:
        layers = (
            packet
            .get("_source", {})
            .get("layers", {})
        )

        for protocol in layers.keys():

            protocol_lower = protocol.lower()

            if protocol_lower == "smtp":
                detected.add("SMTP")

            elif protocol_lower == "imap":
                detected.add("IMAP")

            elif protocol_lower in ("pop", "pop3"):
                detected.add("POP3")

    return sorted(detected)