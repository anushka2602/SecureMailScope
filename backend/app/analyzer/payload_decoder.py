def decode_payload(payload_hex):
    """
    Convert hexadecimal TCP payload into readable text
    where possible.
    """

    try:
        payload_bytes = bytes.fromhex(
            payload_hex.replace(":", "")
        )

        return payload_bytes.decode(
            "utf-8",
            errors="replace"
        )

    except Exception:
        return ""


def decode_stream_payloads(stream):
    """
    Decode all payloads belonging to a TCP stream.
    """

    decoded_payloads = []

    for packet in stream.get("packets", []):

        payload_hex = packet.get(
            "payload_hex",
            ""
        )

        decoded = decode_payload(payload_hex)

        if decoded:
            decoded_payloads.append(decoded)

    return decoded_payloads