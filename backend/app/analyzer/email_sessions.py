from collections import defaultdict


EMAIL_PORTS = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP Submission",
    143: "IMAP",
    993: "IMAPS",
    110: "POP3",
    995: "POP3S",
}


def get_email_protocol(source_port, destination_port):
    """
    Determine the email protocol based on the TCP ports.
    """

    if destination_port in EMAIL_PORTS:
        return EMAIL_PORTS[destination_port]

    if source_port in EMAIL_PORTS:
        return EMAIL_PORTS[source_port]

    return None


def extract_email_sessions(packets):
    """
    Group packets into email-related TCP sessions.
    """

    sessions = defaultdict(
        lambda: {
            "protocol": "Unknown",
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": None,
            "packet_count": 0,
            "tcp_stream": None,
        }
    )

    for packet in packets:

        layers = packet.get("_source", {}).get("layers", {})

        ip_layer = layers.get("ip", {})
        tcp_layer = layers.get("tcp", {})

        if not ip_layer or not tcp_layer:
            continue

        source_ip = ip_layer.get("ip.src")
        destination_ip = ip_layer.get("ip.dst")

        source_port = tcp_layer.get("tcp.srcport")
        destination_port = tcp_layer.get("tcp.dstport")

        if not source_ip or not destination_ip:
            continue

        if not source_port or not destination_port:
            continue

        try:
            source_port = int(source_port)
            destination_port = int(destination_port)
        except (ValueError, TypeError):
            continue

        protocol = get_email_protocol(
            source_port,
            destination_port
        )

        if protocol is None:
            continue

        # TCP stream number assigned by TShark
        tcp_stream = tcp_layer.get("tcp.stream")

        # Create direction-independent session key
        endpoint_a = (source_ip, source_port)
        endpoint_b = (destination_ip, destination_port)

        session_key = tuple(
            sorted([endpoint_a, endpoint_b])
        )

        session = sessions[session_key]

        session["protocol"] = protocol
        session["source_ip"] = source_ip
        session["source_port"] = source_port
        session["destination_ip"] = destination_ip
        session["destination_port"] = destination_port
        session["packet_count"] += 1

        if tcp_stream is not None:
            session["tcp_stream"] = tcp_stream

    return list(sessions.values())