import subprocess
from collections import defaultdict


def _parse_int(value):
    """
    Safely convert a TShark numeric field to int.

    TShark can return multiple values for some fields, separated
    by commas. For TCP reconstruction, use the first value.
    """
    if not value:
        return None

    try:
        return int(str(value).split(",")[0].strip())
    except (TypeError, ValueError):
        return None


def _normalize_hex(payload_hex):
    """Normalize TShark hexadecimal payload output."""
    if not payload_hex:
        return ""

    return (
        payload_hex
        .replace(":", "")
        .replace(" ", "")
        .strip()
    )


def _decode_payload(payload_hex):
    """
    Safely decode hexadecimal TCP payload.

    Returns:
        bytes | None
    """
    if not payload_hex:
        return None

    try:
        return bytes.fromhex(payload_hex)
    except (ValueError, TypeError):
        return None


def _reconstruct_direction(packets):
    """
    Reconstruct one TCP direction from payload-bearing TCP segments.

    The reconstruction is sequence-aware and:

    - sorts segments by TCP sequence number
    - prefers longer segments when sequence numbers are identical
    - detects missing sequence ranges
    - handles retransmissions
    - handles overlapping segments
    - preserves gaps instead of inventing bytes
    """

    if not packets:
        return {
            "payload_hex": "",
            "payload_bytes": 0,
            "complete": True,
            "gaps": [],
            "segments": 0,
            "retransmissions": 0,
            "overlapping_segments": 0,
        }

    valid_segments = []

    for packet in packets:
        sequence = packet.get("sequence_number")

        if sequence is None:
            continue

        payload = packet.get("payload_bytes")

        if payload is None:
            continue

        if not payload:
            continue

        valid_segments.append(
            {
                "sequence_number": sequence,
                "payload": payload,
                "frame_number": packet.get("frame_number"),
            }
        )

    if not valid_segments:
        return {
            "payload_hex": "",
            "payload_bytes": 0,
            "complete": True,
            "gaps": [],
            "segments": len(packets),
            "retransmissions": 0,
            "overlapping_segments": 0,
        }

    # Sort by sequence number first.
    # If multiple segments have the same sequence number,
    # process the longer segment first.
    valid_segments.sort(
        key=lambda segment: (
            segment["sequence_number"],
            -len(segment["payload"]),
        )
    )

    reconstructed = bytearray()
    gaps = []

    retransmissions = 0
    overlapping_segments = 0

    current_end = None

    for segment in valid_segments:
        sequence = segment["sequence_number"]
        payload = segment["payload"]

        segment_start = sequence
        segment_end = sequence + len(payload)

        # First valid segment.
        if current_end is None:
            reconstructed.extend(payload)
            current_end = segment_end
            continue

        # Entire segment has already been reconstructed.
        if segment_end <= current_end:
            retransmissions += 1
            continue

        # Segment begins after the current reconstructed range.
        if segment_start > current_end:
            gaps.append(
                {
                    "start": current_end,
                    "end": segment_start,
                    "length": segment_start - current_end,
                }
            )

            # Do not fabricate the missing bytes.
            reconstructed.extend(payload)

            current_end = segment_end
            continue

        # Segment overlaps the currently reconstructed range.
        if segment_start < current_end:
            overlapping_segments += 1

            overlap = current_end - segment_start

            if overlap < len(payload):
                new_payload = payload[overlap:]

                reconstructed.extend(new_payload)

                current_end = segment_end
            else:
                retransmissions += 1

            continue

        # Segment begins exactly where the current stream ends.
        if segment_start == current_end:
            reconstructed.extend(payload)
            current_end = segment_end

    return {
        "payload_hex": reconstructed.hex(),
        "payload_bytes": len(reconstructed),
        "complete": len(gaps) == 0,
        "gaps": gaps,
        "segments": len(packets),
        "retransmissions": retransmissions,
        "overlapping_segments": overlapping_segments,
    }


def reconstruct_tcp_streams(pcap_path):
    """
    Reconstruct TCP streams from a PCAP using TShark.

    The function:

    1. Extracts TCP payload-bearing packets.
    2. Groups packets by tcp.stream.
    3. Preserves packet-level metadata.
    4. Separates traffic into TCP directions.
    5. Uses relative TCP sequence numbers.
    6. Orders segments by sequence number.
    7. Handles retransmissions and overlaps.
    8. Detects missing sequence ranges.
    9. Produces reconstructed directional streams.

    Missing TCP sequence ranges are reported as gaps.
    No bytes are invented for missing portions of the PCAP.
    """

    command = [
        "tshark",
        "-r",
        str(pcap_path),

        # Use relative TCP sequence numbers.
        "-o",
        "tcp.relative_sequence_numbers:TRUE",

        "-T",
        "fields",

        "-E",
        "separator=\t",

        "-e",
        "tcp.stream",

        "-e",
        "frame.number",

        "-e",
        "ip.src",

        "-e",
        "tcp.srcport",

        "-e",
        "ip.dst",

        "-e",
        "tcp.dstport",

        "-e",
        "tcp.seq",

        "-e",
        "tcp.ack",

        "-e",
        "tcp.len",

        "-e",
        "tcp.flags",

        "-e",
        "tcp.payload",

        "-Y",
        "tcp.payload",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"TShark failed:\n{result.stderr}"
        )

    streams = defaultdict(
        lambda: {
            "stream_id": None,
            "packets": [],
        }
    )

    for line in result.stdout.splitlines():

        if not line.strip():
            continue

        parts = line.split("\t")

        if len(parts) < 11:
            continue

        (
            stream_id,
            frame_number,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            sequence_number,
            acknowledgment_number,
            tcp_length,
            tcp_flags,
            payload_hex,
        ) = parts[:11]

        if not stream_id:
            continue

        payload_hex = _normalize_hex(payload_hex)

        if not payload_hex:
            continue

        # Decode once here.
        payload_bytes = _decode_payload(payload_hex)

        # Ignore malformed payloads instead of crashing
        # the entire PCAP analysis.
        if payload_bytes is None:
            continue

        packet = {
            "frame_number": _parse_int(
                frame_number
            ),
            "source_ip": source_ip,
            "source_port": _parse_int(
                source_port
            ),
            "destination_ip": destination_ip,
            "destination_port": _parse_int(
                destination_port
            ),
            "sequence_number": _parse_int(
                sequence_number
            ),
            "acknowledgment_number": _parse_int(
                acknowledgment_number
            ),
            "tcp_length": _parse_int(
                tcp_length
            ),
            "tcp_flags": tcp_flags,
            "payload_hex": payload_hex,

            # Store decoded bytes so they do not need to be
            # decoded again during reconstruction.
            "payload_bytes": payload_bytes,
        }

        stream = streams[stream_id]

        stream["stream_id"] = stream_id
        stream["packets"].append(packet)

    # Reconstruct each TCP direction independently.
    for stream in streams.values():

        packets = stream["packets"]

        if not packets:
            continue

        directions = defaultdict(list)

        for packet in packets:

            direction = (
                packet["source_ip"],
                packet["source_port"],
                packet["destination_ip"],
                packet["destination_port"],
            )

            directions[direction].append(packet)

        reconstructed_directions = []

        for direction, direction_packets in directions.items():

            (
                source_ip,
                source_port,
                destination_ip,
                destination_port,
            ) = direction

            reconstruction = _reconstruct_direction(
                direction_packets
            )

            reconstruction.update(
                {
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                }
            )

            reconstructed_directions.append(
                reconstruction
            )

        stream["directions"] = reconstructed_directions

    return dict(streams)