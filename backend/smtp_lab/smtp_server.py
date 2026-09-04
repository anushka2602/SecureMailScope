import socket
import ssl
from pathlib import Path


HOST = "127.0.0.1"
PORT = 2525

BASE_DIR = Path(__file__).resolve().parent

# Keep the existing working certificate.
# The insecurity in this lab comes from the TLS configuration.
CERT_FILE = BASE_DIR / "server.crt"
KEY_FILE = BASE_DIR / "server.key"


def send_response(connection, message):
    connection.sendall(
        (message + "\r\n").encode("ascii")
    )


def receive_line(connection):
    data = b""

    while not data.endswith(b"\r\n"):
        chunk = connection.recv(1)

        if not chunk:
            return ""

        data += chunk

        if len(data) > 4096:
            break

    return data.decode(
        "utf-8",
        errors="replace"
    ).strip()


def send_ehlo(connection):
    send_response(connection, "250-localhost")
    send_response(connection, "250-STARTTLS")
    send_response(connection, "250 SIZE 10485760")


def create_insecure_tls_context():
    """
    Create a deliberately weak TLS configuration
    for SecureMailScope laboratory testing.

    This configuration is NOT suitable for production.

    Configuration:
        TLS 1.2 only
        AES-256-CBC cipher
        OpenSSL security level 0
    """

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    # Deliberately enable a legacy AES-CBC cipher.
    #
    # AES256-SHA uses AES-256 in CBC mode and SHA-1
    # for the TLS 1.2 MAC. It is intentionally weaker
    # than modern AEAD suites such as AES-GCM.
    #
    # @SECLEVEL=0 allows this legacy configuration
    # under modern OpenSSL security policies.
    context.set_ciphers(
        "AES256-SHA:@SECLEVEL=0"
    )

    return context


def main():

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        print("Certificate files not found.")
        print("Run generate_cert.py first.")
        return

    print("=" * 60)
    print("SecureMailScope - INSECURE SMTP STARTTLS LAB")
    print("=" * 60)

    print("\nWARNING:")
    print("This server intentionally uses weak cryptography.")
    print("It is for SecureMailScope testing only.")
    print()

    try:
        context = create_insecure_tls_context()
    except Exception as error:
        print(f"Failed to create insecure TLS context: {error}")
        return

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind(
        (HOST, PORT)
    )

    server_socket.listen(1)

    print(f"SMTP server listening on {HOST}:{PORT}")
    print("TLS configuration:")
    print("  Protocol: TLS 1.2")
    print("  Cipher:   AES256-SHA (AES-256-CBC)")
    print("  Security: Intentionally weak")
    print("\nWaiting for client connection...")

    connection, address = server_socket.accept()

    print(f"Client connected: {address}")

    try:

        send_response(
            connection,
            "220 localhost SecureMailScope SMTP Lab"
        )

        while True:

            command = receive_line(connection)

            if not command:
                break

            print(f"CLIENT: {command}")

            command_upper = command.upper()

            if command_upper.startswith("EHLO"):

                send_ehlo(connection)

            elif command_upper.startswith("HELO"):

                send_response(
                    connection,
                    "250 localhost"
                )

            elif command_upper == "STARTTLS":

                send_response(
                    connection,
                    "220 2.0.0 Ready to start TLS"
                )

                print(
                    "Starting intentionally weak TLS handshake..."
                )

                tls_connection = context.wrap_socket(
                    connection,
                    server_side=True
                )

                print("TLS handshake completed.")

                print(
                    f"Negotiated TLS version: "
                    f"{tls_connection.version()}"
                )

                print(
                    f"Negotiated cipher: "
                    f"{tls_connection.cipher()}"
                )

                connection = tls_connection

                # RFC 5321 requires EHLO again after STARTTLS.
                continue

            elif command_upper.startswith("MAIL FROM"):

                send_response(
                    connection,
                    "250 2.1.0 OK"
                )

            elif command_upper.startswith("RCPT TO"):

                send_response(
                    connection,
                    "250 2.1.5 OK"
                )

            elif command_upper == "DATA":

                send_response(
                    connection,
                    "354 End data with <CR><LF>.<CR><LF>"
                )

                while True:

                    line = receive_line(connection)

                    if line == ".":
                        break

                send_response(
                    connection,
                    "250 2.0.0 Message accepted"
                )

            elif command_upper == "QUIT":

                send_response(
                    connection,
                    "221 2.0.0 Bye"
                )

                break

            else:

                send_response(
                    connection,
                    "250 OK"
                )

    except Exception as error:

        print(f"\nServer error: {error}")

    finally:

        try:
            connection.close()
        except Exception:
            pass

        server_socket.close()

        print("\nSMTP server stopped.")


if __name__ == "__main__":
    main()

