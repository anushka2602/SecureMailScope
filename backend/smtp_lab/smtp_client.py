import socket
import ssl


HOST = "127.0.0.1"
PORT = 2525


def receive_response(sock):
    """
    Read an SMTP response.

    Handles multiline responses such as:

        250-localhost
        250-STARTTLS
        250 SIZE 10485760
    """

    lines = []

    while True:

        data = b""

        while not data.endswith(b"\r\n"):

            chunk = sock.recv(1)

            if not chunk:
                return lines

            data += chunk

        line = data.decode(
            "utf-8",
            errors="replace"
        ).strip()

        print(f"SERVER: {line}")

        lines.append(line)

        # SMTP multiline response ends when the fourth
        # character is a space rather than a hyphen.
        if len(line) >= 4 and line[3] == " ":
            break

    return lines


def send_command(sock, command):

    print(f"CLIENT: {command}")

    sock.sendall(
        (command + "\r\n").encode("ascii")
    )

    return receive_response(sock)


def create_insecure_tls_context():
    """
    Create a deliberately weak TLS client context
    for the SecureMailScope laboratory.

    This configuration is NOT suitable for production.

    Configuration:
        TLS 1.2 only
        AES256-SHA
        AES-256-CBC
        OpenSSL security level 0
        Certificate verification disabled
    """

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )

    # The lab server intentionally supports TLS 1.2 only.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # The certificate is locally generated for the lab.
    # We intentionally disable certificate verification
    # because this client is only used for local testing.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Deliberately use the weak legacy TLS 1.2 cipher
    # configured by the insecure SMTP server.
    #
    # AES256-SHA =
    # TLS_RSA_WITH_AES_256_CBC_SHA
    #
    # It uses AES-256-CBC and SHA-1 rather than a
    # modern AEAD cipher such as AES-GCM.
    context.set_ciphers(
        "AES256-SHA:@SECLEVEL=0"
    )

    return context


def main():

    print("=" * 60)
    print("SecureMailScope - SMTP STARTTLS Client")
    print("=" * 60)

    sock = socket.create_connection(
        (HOST, PORT)
    )

    try:

        # Receive SMTP greeting.
        receive_response(sock)

        # Begin SMTP session.
        send_command(
            sock,
            "EHLO localhost"
        )

        # Request STARTTLS.
        send_command(
            sock,
            "STARTTLS"
        )

        print("\nStarting TLS handshake...")

        # Create intentionally weak TLS context
        # compatible with our insecure lab server.
        context = create_insecure_tls_context()

        tls_sock = context.wrap_socket(
            sock,
            server_hostname="localhost"
        )

        print("TLS handshake completed.")
        print(
            f"Negotiated TLS version: "
            f"{tls_sock.version()}"
        )
        print(
            f"Negotiated cipher: "
            f"{tls_sock.cipher()}"
        )

        # RFC 5321 requires EHLO again after STARTTLS.
        send_command(
            tls_sock,
            "EHLO localhost"
        )

        # Send test email transaction.
        send_command(
            tls_sock,
            "MAIL FROM:<alice@localhost>"
        )

        send_command(
            tls_sock,
            "RCPT TO:<bob@localhost>"
        )

        send_command(
            tls_sock,
            "DATA"
        )

        message = (
            "From: alice@localhost\r\n"
            "To: bob@localhost\r\n"
            "Subject: SecureMailScope Test\r\n"
            "\r\n"
            "This is a local SMTP STARTTLS test message.\r\n"
            ".\r\n"
        )

        print("CLIENT: Sending test email")

        tls_sock.sendall(
            message.encode("utf-8")
        )

        receive_response(tls_sock)

        # End SMTP session.
        send_command(
            tls_sock,
            "QUIT"
        )

        tls_sock.close()

    finally:

        try:
            sock.close()
        except Exception:
            pass

    print("\nSMTP client completed.")


if __name__ == "__main__":
    main()