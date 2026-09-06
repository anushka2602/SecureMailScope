def _decode_payload(payload_hex):
    """
    Decode hexadecimal payload into bytes.

    Returns:
        bytes
    """

    if not payload_hex:
        return b""

    try:
        return bytes.fromhex(payload_hex)
    except (ValueError, TypeError):
        return b""


def _decode_text(payload_bytes):
    """
    Decode bytes into text.

    Invalid UTF-8 bytes are replaced instead of raising
    an exception. This keeps the decoder compatible with
    existing string-based callers.
    """

    if not payload_bytes:
        return ""

    return payload_bytes.decode(
        "utf-8",
        errors="replace"
    )


def decode_stream_payloads(stream):
    """
    Decode reconstructed TCP stream directions.

    IMPORTANT:
    This function intentionally returns a list of strings.

    Existing callers such as starttls_analyzer.py expect:

        list[str]

    and may perform operations such as:

        "\\n".join(payloads)
        payload.splitlines()

    Therefore this function MUST NOT return dictionaries.

    The TCP reconstruction layer provides the reconstructed
    directional payloads. This function simply converts those
    payloads into strings.
    """

    directions = stream.get(
        "directions",
        []
    )

    decoded_payloads = []

    for direction in directions:

        payload_hex = direction.get(
            "payload_hex",
            ""
        )

        payload_bytes = _decode_payload(
            payload_hex
        )

        if not payload_bytes:
            continue

        decoded_text = _decode_text(
            payload_bytes
        )

        decoded_payloads.append(
            decoded_text
        )

    return decoded_payloads