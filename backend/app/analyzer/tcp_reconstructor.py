import subprocess
from collections import defaultdict


def reconstruct_tcp_streams(pcap_path):
    """
    Reconstruct TCP streams from a PCAP using TShark.
    """

    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
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

        if len(parts) < 6:
            continue

        (
            stream_id,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            payload_hex,
        ) = parts[:6]

        if not stream_id:
            continue

        if not payload_hex:
            continue

        stream = streams[stream_id]

        stream["stream_id"] = stream_id

        stream["packets"].append(
            {
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "payload_hex": payload_hex,
            }
        )

    return dict(streams)