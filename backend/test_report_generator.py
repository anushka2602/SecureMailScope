from app.reports.report_generator import (
    build_report,
    report_to_html,
)


def test_forward_secrecy_uses_explicit_feature_value():
    analysis = {
        "sessions": [
            {
                "stream_id": "1",
                "protocol": "SMTP",
                "features": {"forward_secrecy": 1},
                "tls": {},
                "starttls": {"encrypted_after_starttls": True},
                "certificate": {},
                "posture": {},
            }
        ]
    }

    report = build_report(analysis)

    assert (
        report["sessions"][0]["cryptographic_analysis"]
        ["forward_secrecy"]
        == "Enabled"
    )
    assert "Forward Secrecy" in report_to_html(analysis)
    assert "Enabled" in report_to_html(analysis)
