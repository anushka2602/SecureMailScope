import json
import subprocess
from pathlib import Path


def parse_pcap(pcap_path: str):
    """
    Run TShark against a PCAP file and return packet information.
    """

    path = Path(pcap_path)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    command = [
        "tshark",
        "-r",
        str(path),
        "-T",
        "json",
        "-x",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"TShark failed:\n{result.stderr}"
        )

    if not result.stdout.strip():
        return []

    return json.loads(result.stdout)