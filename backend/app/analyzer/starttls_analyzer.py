STARTTLS_COMMANDS = {
    "SMTP": ["STARTTLS"],
    "IMAP": ["STARTTLS"],
    "POP3": ["STLS"],
}


def _normalize_protocol(protocol):
    """
    Normalize protocol names used by the different analyzers.
    """
    if not protocol:
        return None

    protocol_upper = protocol.upper()

    if protocol_upper.startswith("SMTP"):
        return "SMTP"

    if protocol_upper.startswith("IMAP"):
        return "IMAP"

    if protocol_upper.startswith("POP3"):
        return "POP3"

    return protocol_upper


def analyze_starttls(protocol, payloads, tls_detected=False):
    """
    Analyze plaintext email traffic for STARTTLS/STLS and
    determine whether the connection subsequently upgraded to TLS.

    Parameters:
        protocol:
            SMTP, IMAP, or POP3.

        payloads:
            Decoded plaintext TCP payloads from the stream.

        tls_detected:
            True when TLS traffic is observed on the same stream.
    """

    normalized_protocol = _normalize_protocol(protocol)

    result = {
        "starttls_supported": False,
        "starttls_requested": False,
        "tls_upgrade_detected": False,
        "commands_found": [],
    }

    if not payloads:
        return result

    commands = STARTTLS_COMMANDS.get(normalized_protocol, [])

    combined_payload = "\n".join(payloads).upper()

    # ---------------------------------------------------------
    # 1. Detect STARTTLS/STLS capability or command
    # ---------------------------------------------------------

    for command in commands:
        if command in combined_payload:
            result["starttls_supported"] = True

        # Look for the actual client command.
        for payload in payloads:
            lines = payload.splitlines()

            for line in lines:
                stripped_line = line.strip().upper()

                if stripped_line == command:
                    result["starttls_requested"] = True

                    if command not in result["commands_found"]:
                        result["commands_found"].append(command)

    # ---------------------------------------------------------
    # 2. Detect TLS upgrade
    # ---------------------------------------------------------

    if result["starttls_requested"] and tls_detected:
        result["tls_upgrade_detected"] = True

    return result