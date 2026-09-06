from pathlib import Path
import io
import shutil
import tempfile

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app.analyzer.feature_extractor import extract_features_from_pcap
from app.security.security_posture import analyze_security_posture
from app.reports.report_generator import (
    _get_certificate_status,
    build_report,
    report_to_json,
    report_to_html,
)


app = FastAPI(
    title="SecureMailScope",
    description=(
        "AI-Assisted Cryptographic Security Posture Assessment "
        "for Secure Email Communications"
    ),
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Stores the most recently completed analysis.
# This is intentionally in-memory for the current hackathon prototype.
latest_analysis = None


@app.get("/")
def root():
    return {
        "project": "SecureMailScope",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    global latest_analysis

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    allowed_extensions = {".pcap", ".pcapng"}
    extension = Path(file.filename).suffix.lower()

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported.",
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            shutil.copyfileobj(file.file, temp_file)

        sessions = extract_features_from_pcap(str(temp_path))

        if not sessions:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No SMTP, IMAP, or POP3 sessions were detected "
                    "in the PCAP."
                ),
            )

        analyzed_sessions = []

        for session in sessions:
            posture = analyze_security_posture(
                session["features"]
            )

            analyzed_sessions.append(
                {
                    "stream_id": session["stream_id"],
                    "protocol": session["protocol"],
                    "features": session["features"],
                    "tls": session["tls"],
                    "starttls": session["starttls"],
                    "certificate": session["certificate"],
                    "posture": posture,
                }
            )

        latest_analysis = {
            "filename": file.filename,
            "session_count": len(analyzed_sessions),
            "sessions": analyzed_sessions,
        }

        return latest_analysis

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {error}",
        )

    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()


@app.get("/report/json")
def export_json_report():
    if latest_analysis is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No analysis available. "
                "Upload and analyze a PCAP first."
            ),
        )

    json_content = report_to_json(latest_analysis)

    return Response(
        content=json_content,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                'attachment; filename="securemailscope_report.json"'
            )
        },
    )


@app.get("/report/html")
def export_html_report():
    if latest_analysis is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No analysis available. "
                "Upload and analyze a PCAP first."
            ),
        )

    html_content = report_to_html(latest_analysis)

    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": (
                'attachment; filename="securemailscope_report.html"'
            )
        },
    )


@app.get("/report/pdf")
def export_pdf_report():
    if latest_analysis is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No analysis available. "
                "Upload and analyze a PCAP first."
            ),
        )

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import (
            ParagraphStyle,
            getSampleStyleSheet,
        )
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            KeepTogether,
        )

        report = build_report(latest_analysis)

        metadata = report.get(
            "report_metadata",
            {},
        )

        summary = report.get(
            "executive_summary",
            {},
        )

        sessions = report.get(
            "sessions",
            [],
        ) or []

        buffer = io.BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=(
                "SecureMailScope Cryptographic "
                "Security Posture Report"
            ),
            author="SecureMailScope",
            subject=(
                "AI-assisted passive cryptographic "
                "security assessment"
            ),
            allowSplitting=1,
        )

        styles = getSampleStyleSheet()

        # =========================================================
        # COLORS
        # =========================================================

        DARK_RED = colors.HexColor("#6f1a07")
        DARK_RED_2 = colors.HexColor("#4d1206")
        RED = colors.HexColor("#a52a16")

        CREAM = colors.HexColor("#f7f3e3")
        WARM_LIGHT = colors.HexColor("#faf7f1")
        WARM_PANEL = colors.HexColor("#f1e9df")

        BORDER = colors.HexColor("#d4c8bc")
        TEXT = colors.HexColor("#222222")
        MUTED = colors.HexColor("#66615c")

        GREEN = colors.HexColor("#2e6b4d")
        ORANGE = colors.HexColor("#a65d16")

        SOFT_RED = colors.HexColor("#f7e8e3")
        SOFT_ORANGE = colors.HexColor("#f8eee1")
        SOFT_GREEN = colors.HexColor("#e8f2ec")

        # =========================================================
        # STYLES
        # =========================================================

        title_style = ParagraphStyle(
            "SecureMailScopeTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=DARK_RED,
            spaceAfter=3,
            alignment=TA_LEFT,
        )

        subtitle_style = ParagraphStyle(
            "SecureMailScopeSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=MUTED,
            spaceAfter=10,
        )

        section_style = ParagraphStyle(
            "SecureMailScopeSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=DARK_RED,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True,
        )

        subsection_style = ParagraphStyle(
            "SecureMailScopeSubsection",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=DARK_RED,
            spaceBefore=5,
            spaceAfter=5,
            keepWithNext=True,
        )

        session_style = ParagraphStyle(
            "SecureMailScopeSession",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=14,
            textColor=DARK_RED,
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True,
        )

        body_style = ParagraphStyle(
            "SecureMailScopeBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.4,
            leading=11.5,
            textColor=TEXT,
        )

        small_style = ParagraphStyle(
            "SecureMailScopeSmall",
            parent=body_style,
            fontSize=7.5,
            leading=9.8,
        )

        tiny_style = ParagraphStyle(
            "SecureMailScopeTiny",
            parent=body_style,
            fontSize=6.9,
            leading=8.8,
        )

        label_style = ParagraphStyle(
            "SecureMailScopeLabel",
            parent=small_style,
            fontName="Helvetica-Bold",
            textColor=DARK_RED,
        )

        centered_style = ParagraphStyle(
            "SecureMailScopeCentered",
            parent=body_style,
            alignment=TA_CENTER,
        )

        centered_small_style = ParagraphStyle(
            "SecureMailScopeCenteredSmall",
            parent=small_style,
            alignment=TA_CENTER,
        )

        metric_value_style = ParagraphStyle(
            "SecureMailScopeMetricValue",
            parent=body_style,
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            alignment=TA_CENTER,
        )

        priority_style = ParagraphStyle(
            "SecureMailScopePriority",
            parent=small_style,
            fontName="Helvetica-Bold",
            textColor=RED,
        )

        finding_style = ParagraphStyle(
            "SecureMailScopeFinding",
            parent=small_style,
            leftIndent=8,
            firstLineIndent=-8,
            spaceAfter=3,
        )

        recommendation_style = ParagraphStyle(
            "SecureMailScopeRecommendation",
            parent=small_style,
            leftIndent=8,
            firstLineIndent=-8,
            spaceAfter=3,
        )

        note_style = ParagraphStyle(
            "SecureMailScopeNote",
            parent=small_style,
            textColor=MUTED,
            leading=10,
        )

        footer_style = ParagraphStyle(
            "SecureMailScopeFooter",
            parent=tiny_style,
            textColor=MUTED,
            alignment=TA_CENTER,
        )

        story = []

        # =========================================================
        # HELPERS
        # =========================================================

        def display_value(
            value,
            fallback="Not observed",
        ):
            if value is None:
                return fallback

            if isinstance(value, str):
                if not value.strip():
                    return fallback

                return value

            return str(value)

        def bool_display(value):
            if value is True:
                return "Yes"

            if value is False:
                return "No"

            return "Not determined"

        def fs_display(value):
            if value is True or value == 1 or value == "Enabled":
                return "Enabled"

            if value is False or value == 0 or value == "Disabled":
                return "Disabled"

            return "Not determined"

        def severity_rank(severity):
            order = {
                "Critical": 4,
                "High": 3,
                "Medium": 2,
                "Low": 1,
            }

            return order.get(
                str(severity),
                0,
            )

        def severity_background(severity):
            severity = str(
                severity or ""
            ).strip()

            if severity == "Critical":
                return SOFT_RED

            if severity == "High":
                return SOFT_RED

            if severity == "Medium":
                return SOFT_ORANGE

            if severity == "Low":
                return SOFT_GREEN

            return WARM_LIGHT

        def get_session_risk(session):
            risk = session.get(
                "risk"
            ) or {}

            return {
                "severity": risk.get(
                    "severity",
                    "Unknown",
                ),
                "score": risk.get(
                    "score",
                    0,
                ),
                "findings": risk.get(
                    "findings",
                    [],
                ) or [],
                "recommendations": risk.get(
                    "recommendations",
                    [],
                ) or [],
                "ml_label": risk.get(
                    "ml_label"
                ),
                "confidence": risk.get(
                    "confidence"
                ),
                "anomaly": risk.get(
                    "anomaly"
                ) or {},
            }

        def finding_message(finding):
            if isinstance(finding, dict):
                return finding.get("message") or "Unknown finding"

            return finding

        def make_detail_table(
            rows,
            left_width=42 * mm,
            right_width=130 * mm,
        ):
            table = Table(
                rows,
                colWidths=[
                    left_width,
                    right_width,
                ],
            )

            table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, -1),
                            WARM_PANEL,
                        ),
                        (
                            "BACKGROUND",
                            (1, 0),
                            (1, -1),
                            WARM_LIGHT,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            BORDER,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            6,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            6,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            4.5,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            4.5,
                        ),
                    ]
                )
            )

            return table

        def make_section_banner(
            title,
            background=DARK_RED,
        ):
            banner = Table(
                [
                    [
                        Paragraph(
                            title,
                            ParagraphStyle(
                                "BannerText",
                                parent=small_style,
                                fontName="Helvetica-Bold",
                                fontSize=8.5,
                                leading=10,
                                textColor=colors.white,
                            ),
                        )
                    ]
                ],
                colWidths=[170 * mm],
            )

            banner.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            background,
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                    ]
                )
            )

            return banner

        def make_metric_card(
            label,
            value,
            background=CREAM,
        ):
            table = Table(
                [
                    [
                        Paragraph(
                            label,
                            centered_small_style,
                        )
                    ],
                    [
                        Paragraph(
                            value,
                            metric_value_style,
                        )
                    ],
                ],
                colWidths=[42.5 * mm],
                rowHeights=[
                    9 * mm,
                    13 * mm,
                ],
            )

            table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            DARK_RED,
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "BACKGROUND",
                            (0, 1),
                            (-1, 1),
                            background,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            BORDER,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "MIDDLE",
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                    ]
                )
            )

            return table

        def page_header_footer(
            canvas,
            doc,
        ):
            canvas.saveState()

            width, height = A4

            # Header rule
            canvas.setStrokeColor(BORDER)
            canvas.setLineWidth(0.5)

            canvas.line(
                15 * mm,
                height - 11 * mm,
                width - 15 * mm,
                height - 11 * mm,
            )

            canvas.setFont(
                "Helvetica",
                6.8,
            )

            canvas.setFillColor(
                MUTED
            )

            canvas.drawString(
                15 * mm,
                height - 8.5 * mm,
                "SECUREMAILSCOPE",
            )

            canvas.drawRightString(
                width - 15 * mm,
                height - 8.5 * mm,
                "Cryptographic Security Posture Report",
            )

            # Footer rule
            canvas.line(
                15 * mm,
                11 * mm,
                width - 15 * mm,
                11 * mm,
            )

            canvas.setFont(
                "Helvetica",
                6.8,
            )

            canvas.drawString(
                15 * mm,
                7 * mm,
                "AI-assisted passive network forensic assessment",
            )

            canvas.drawRightString(
                width - 15 * mm,
                7 * mm,
                f"Page {doc.page}",
            )

            canvas.restoreState()

        # =========================================================
        # HEADER
        # =========================================================

        story.append(
            Paragraph(
                "SecureMailScope",
                title_style,
            )
        )

        story.append(
            Paragraph(
                "Cryptographic Security Posture Assessment",
                ParagraphStyle(
                    "ReportSubtitleHeading",
                    parent=section_style,
                    fontSize=11.5,
                    leading=14,
                    spaceBefore=0,
                    spaceAfter=5,
                ),
            )
        )

        story.append(
            Paragraph(
                "AI-assisted passive network forensic analysis "
                "of SMTP, IMAP and POP3 communications. The "
                "framework reconstructs observed cryptographic "
                "behavior, evaluates TLS and X.509 evidence, "
                "detects security weaknesses and adds ML-based "
                "risk and anomaly intelligence.",
                subtitle_style,
            )
        )

        metadata_table = Table(
            [
                [
                    Paragraph(
                        "<b>Source PCAP</b>",
                        body_style,
                    ),
                    Paragraph(
                        display_value(
                            metadata.get(
                                "source_file"
                            )
                        ),
                        body_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Generated</b>",
                        body_style,
                    ),
                    Paragraph(
                        display_value(
                            metadata.get(
                                "generated_at"
                            )
                        ),
                        body_style,
                    ),
                ],
            ],
            colWidths=[
                35 * mm,
                140 * mm,
            ],
        )

        metadata_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        WARM_PANEL,
                    ),
                    (
                        "BACKGROUND",
                        (1, 0),
                        (1, -1),
                        WARM_LIGHT,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5.5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5.5,
                    ),
                ]
            )
        )

        story.append(
            metadata_table
        )

        # =========================================================
        # EXECUTIVE SUMMARY
        # =========================================================

        story.append(
            Paragraph(
                "Executive Summary",
                section_style,
            )
        )

        severity_counts = summary.get(
            "severity_counts",
            {},
        ) or {}

        overall_severity = display_value(
            summary.get(
                "overall_severity"
            ),
            "Unknown",
        )

        total_sessions = summary.get(
            "total_sessions",
            len(sessions),
        )

        try:
            average_score = float(
                summary.get(
                    "average_risk_score",
                    0,
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            average_score = 0.0

        critical_count = severity_counts.get(
            "Critical",
            0,
        )

        high_count = severity_counts.get(
            "High",
            0,
        )

        medium_count = severity_counts.get(
            "Medium",
            0,
        )

        low_count = severity_counts.get(
            "Low",
            0,
        )

        summary_cards = Table(
            [
                [
                    make_metric_card(
                        "Overall Risk",
                        overall_severity,
                        severity_background(
                            overall_severity
                        ),
                    ),
                    make_metric_card(
                        "Sessions",
                        str(total_sessions),
                    ),
                    make_metric_card(
                        "Average Score",
                        f"{average_score:.2f} / 100",
                    ),
                    make_metric_card(
                        "Critical / High",
                        f"{critical_count} / {high_count}",
                        SOFT_RED
                        if (
                            critical_count
                            or high_count
                        )
                        else SOFT_GREEN,
                    ),
                ]
            ],
            colWidths=[
                42.5 * mm,
                42.5 * mm,
                42.5 * mm,
                42.5 * mm,
            ],
        )

        summary_cards.setStyle(
            TableStyle(
                [
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(
            summary_cards
        )

        story.append(
            Spacer(
                1,
                6,
            )
        )

        severity_table = Table(
            [
                [
                    Paragraph(
                        "<b>Critical</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>High</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Medium</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Low</b>",
                        centered_small_style,
                    ),
                ],
                [
                    Paragraph(
                        str(critical_count),
                        metric_value_style,
                    ),
                    Paragraph(
                        str(high_count),
                        metric_value_style,
                    ),
                    Paragraph(
                        str(medium_count),
                        metric_value_style,
                    ),
                    Paragraph(
                        str(low_count),
                        metric_value_style,
                    ),
                ],
            ],
            colWidths=[
                42.5 * mm,
                42.5 * mm,
                42.5 * mm,
                42.5 * mm,
            ],
        )

        severity_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, 0),
                        DARK_RED_2,
                    ),
                    (
                        "BACKGROUND",
                        (1, 0),
                        (1, 0),
                        DARK_RED,
                    ),
                    (
                        "BACKGROUND",
                        (2, 0),
                        (2, 0),
                        ORANGE,
                    ),
                    (
                        "BACKGROUND",
                        (3, 0),
                        (3, 0),
                        GREEN,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "BACKGROUND",
                        (0, 1),
                        (-1, 1),
                        WARM_LIGHT,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        story.append(
            severity_table
        )

        story.append(
            Spacer(
                1,
                6,
            )
        )

        story.append(
            Paragraph(
                "The security posture score is derived from "
                "deterministic cryptographic security rules. "
                "The AI/ML layer is complementary: it provides "
                "risk classification, confidence and TLS anomaly "
                "intelligence. These two signals are reported "
                "separately so that observed security evidence "
                "is not confused with model output.",
                note_style,
            )
        )

        # =========================================================
        # PRIORITY FINDINGS
        # =========================================================

        story.append(
            Paragraph(
                "Priority Findings",
                section_style,
            )
        )

        priority_items = []

        for index, session in enumerate(
            sessions,
            start=1,
        ):
            risk = get_session_risk(
                session
            )

            for finding in risk["findings"]:
                priority_items.append(
                    {
                        "session": index,
                        "stream": session.get(
                            "stream_id",
                            "Unknown",
                        ),
                        "protocol": session.get(
                            "protocol",
                            "Unknown",
                        ),
                        "severity": risk[
                            "severity"
                        ],
                        "score": risk[
                            "score"
                        ],
                        "finding": finding,
                    }
                )

        priority_items.sort(
            key=lambda item: (
                -severity_rank(
                    item["severity"]
                ),
                -float(
                    item["score"]
                    or 0
                ),
                str(finding_message(item["finding"])),
            )
        )

        if priority_items:

            priority_rows = [
                [
                    Paragraph(
                        "<b>#</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Session</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Severity</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Finding</b>",
                        centered_small_style,
                    ),
                ]
            ]

            for rank, item in enumerate(
                priority_items[:10],
                start=1,
            ):

                severity = item[
                    "severity"
                ]

                priority_rows.append(
                    [
                        Paragraph(
                            str(rank),
                            centered_small_style,
                        ),
                        Paragraph(
                            (
                                f'S{item["session"]} '
                                f'/ Stream {item["stream"]} '
                                f'/ {item["protocol"]}'
                            ),
                            tiny_style,
                        ),
                        Paragraph(
                            (
                                f'{severity} '
                                f'({item["score"]}/100)'
                            ),
                            priority_style,
                        ),
                        Paragraph(
                            display_value(
                                finding_message(item["finding"])
                            ),
                            tiny_style,
                        ),
                    ]
                )

            priority_table = Table(
                priority_rows,
                colWidths=[
                    12 * mm,
                    46 * mm,
                    35 * mm,
                    77 * mm,
                ],
                repeatRows=1,
            )

            priority_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            DARK_RED,
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "BACKGROUND",
                            (0, 1),
                            (-1, -1),
                            WARM_LIGHT,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            BORDER,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                        (
                            "BACKGROUND",
                            (2, 1),
                            (2, -1),
                            SOFT_RED,
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                    ]
                )
            )

            story.append(
                priority_table
            )

            if len(priority_items) > 10:

                story.append(
                    Spacer(
                        1,
                        4,
                    )
                )

                story.append(
                    Paragraph(
                        (
                            f'{len(priority_items) - 10} additional '
                            "finding(s) are detailed in the session analysis."
                        ),
                        note_style,
                    )
                )

        else:

            story.append(
                Paragraph(
                    "No security findings were recorded.",
                    note_style,
                )
            )

        # =========================================================
        # PROTOCOL DISTRIBUTION
        # =========================================================

        story.append(
            Paragraph(
                "Protocol Distribution",
                section_style,
            )
        )

        protocols = summary.get(
            "protocols",
            {},
        ) or {}

        protocol_rows = [
            [
                Paragraph(
                    "<b>Protocol</b>",
                    centered_style,
                ),
                Paragraph(
                    "<b>Sessions</b>",
                    centered_style,
                ),
                Paragraph(
                    "<b>Share</b>",
                    centered_style,
                ),
            ]
        ]

        for protocol, count in protocols.items():

            try:
                percentage = (
                    float(count)
                    / float(total_sessions)
                    * 100
                    if total_sessions
                    else 0
                )
            except (
                TypeError,
                ValueError,
            ):
                percentage = 0

            protocol_rows.append(
                [
                    Paragraph(
                        display_value(
                            protocol
                        ),
                        centered_style,
                    ),
                    Paragraph(
                        str(count),
                        centered_style,
                    ),
                    Paragraph(
                        f"{percentage:.1f}%",
                        centered_style,
                    ),
                ]
            )

        protocol_table = Table(
            protocol_rows,
            colWidths=[
                56 * mm,
                56 * mm,
                58 * mm,
            ],
            repeatRows=1,
        )

        protocol_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        DARK_RED,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "BACKGROUND",
                        (0, 1),
                        (-1, -1),
                        WARM_LIGHT,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(
            protocol_table
        )

        # =========================================================
        # SESSION ANALYSIS
        # =========================================================

        story.append(
            Paragraph(
                "Session Analysis",
                section_style,
            )
        )

        story.append(
            Paragraph(
                "Each session below preserves the observed "
                "cryptographic evidence and separates deterministic "
                "security findings from AI/ML intelligence.",
                note_style,
            )
        )

        story.append(
            Spacer(
                1,
                4,
            )
        )

        for index, session in enumerate(
            sessions,
            start=1,
        ):

            risk = session.get(
                "risk"
            ) or {}

            crypto = session.get(
                "cryptographic_analysis"
            ) or {}

            certificate = session.get(
                "certificate"
            ) or {}

            starttls = session.get(
                "starttls"
            ) or {}

            # -----------------------------------------------------
            # Certificate status
            # -----------------------------------------------------

            certificate_status = _get_certificate_status(session)

            # -----------------------------------------------------
            # Security posture
            # -----------------------------------------------------

            security_severity = display_value(
                risk.get(
                    "severity"
                ),
                "Unknown",
            )

            security_score = risk.get(
                "score"
            )

            if security_score is None:
                security_score = "N/A"

            # -----------------------------------------------------
            # Crypto details
            # -----------------------------------------------------

            tls_version = display_value(
                crypto.get(
                    "tls_version"
                )
            )

            cipher_suite = display_value(
                crypto.get(
                    "cipher_suite"
                )
            )

            key_exchange = display_value(
                crypto.get(
                    "key_exchange"
                )
            )

            forward_secrecy = fs_display(
                crypto.get(
                    "forward_secrecy"
                )
            )

            # -----------------------------------------------------
            # Session heading
            # -----------------------------------------------------

            session_heading = Paragraph(
                (
                    f'Session {index} — '
                    f'Stream {display_value(session.get("stream_id"))} — '
                    f'{display_value(session.get("protocol"))}'
                ),
                session_style,
            )

            # -----------------------------------------------------
            # Security posture table
            # -----------------------------------------------------

            posture_rows = [
                [
                    Paragraph(
                        "<b>Security Posture</b>",
                        label_style,
                    ),
                    Paragraph(
                        (
                            f"{security_severity} "
                            f"({security_score}/100)"
                        ),
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Negotiated TLS</b>",
                        label_style,
                    ),
                    Paragraph(
                        tls_version,
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Negotiated Cipher</b>",
                        label_style,
                    ),
                    Paragraph(
                        cipher_suite,
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Key Exchange</b>",
                        label_style,
                    ),
                    Paragraph(
                        key_exchange,
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Forward Secrecy</b>",
                        label_style,
                    ),
                    Paragraph(
                        forward_secrecy,
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Certificate Status</b>",
                        label_style,
                    ),
                    Paragraph(
                        certificate_status,
                        small_style,
                    ),
                ],
            ]

            posture_table = make_detail_table(
                posture_rows
            )

            # -----------------------------------------------------
            # Certificate Analysis
            # -----------------------------------------------------

            certificate_rows = [
                [
                    Paragraph(
                        "<b>Certificate Present</b>",
                        label_style,
                    ),
                    Paragraph(
                        bool_display(
                            certificate.get(
                                "certificate_present"
                            )
                        ),
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Subject</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "subject"
                            )
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Issuer</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "issuer"
                            )
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Valid From</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "valid_from"
                            )
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Valid Until</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "valid_until"
                            )
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Public Key</b>",
                        label_style,
                    ),
                    Paragraph(
                        (
                            f'{display_value(certificate.get("public_key_algorithm"))} '
                            f'({display_value(certificate.get("public_key_length"), "N/A")} bits)'
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Signature Algorithm</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "signature_algorithm"
                            )
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Certificate Version</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "certificate_version"
                            )
                        ),
                        tiny_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>SHA-256 Fingerprint</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            certificate.get(
                                "fingerprint_sha256"
                            )
                        ),
                        tiny_style,
                    ),
                ],
            ]

            certificate_table = make_detail_table(
                certificate_rows
            )

            # -----------------------------------------------------
            # STARTTLS Analysis
            # -----------------------------------------------------

            starttls_rows = [
                [
                    Paragraph(
                        "<b>STARTTLS Supported</b>",
                        label_style,
                    ),
                    Paragraph(
                        bool_display(
                            starttls.get(
                                "starttls_supported"
                            )
                        ),
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>STARTTLS Requested</b>",
                        label_style,
                    ),
                    Paragraph(
                        bool_display(
                            starttls.get(
                                "starttls_requested"
                            )
                        ),
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>TLS Upgrade Detected</b>",
                        label_style,
                    ),
                    Paragraph(
                        bool_display(
                            starttls.get(
                                "encrypted_after_starttls"
                            )
                        ),
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Commands Observed</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            ", ".join(
                                starttls.get(
                                    "commands_found",
                                    [],
                                ) or []
                            )
                        ),
                        small_style,
                    ),
                ],
            ]

            starttls_table = make_detail_table(
                starttls_rows
            )

            # -----------------------------------------------------
            # AI / ML Intelligence
            # -----------------------------------------------------

            ml_label = risk.get(
                "ml_label"
            )

            if ml_label is None:
                ml_label = "Not available"

            ml_confidence = risk.get(
                "confidence"
            )

            if ml_confidence is not None:

                try:
                    ml_confidence_text = (
                        f"{float(ml_confidence) * 100:.2f}%"
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    ml_confidence_text = str(
                        ml_confidence
                    )

            else:

                ml_confidence_text = "Not available"

            anomaly = risk.get(
                "anomaly"
            ) or {}

            anomaly_detected = anomaly.get(
                "is_anomaly"
            )

            if anomaly_detected is True:
                anomaly_text = "Detected"

            elif anomaly_detected is False:
                anomaly_text = "Not detected"

            else:
                anomaly_text = "Not determined"

            anomaly_score = anomaly.get(
                "anomaly_score"
            )

            if anomaly_score is None:

                anomaly_score_text = "Not available"

            else:

                try:
                    anomaly_score_text = (
                        f"{float(anomaly_score):.4f}"
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    anomaly_score_text = str(
                        anomaly_score
                    )

            ai_rows = [
                [
                    Paragraph(
                        "<b>ML Risk Classification</b>",
                        label_style,
                    ),
                    Paragraph(
                        display_value(
                            ml_label,
                            "Not available",
                        ),
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>ML Confidence</b>",
                        label_style,
                    ),
                    Paragraph(
                        ml_confidence_text,
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>TLS Anomaly</b>",
                        label_style,
                    ),
                    Paragraph(
                        anomaly_text,
                        small_style,
                    ),
                ],
                [
                    Paragraph(
                        "<b>Anomaly Score</b>",
                        label_style,
                    ),
                    Paragraph(
                        anomaly_score_text,
                        small_style,
                    ),
                ],
            ]

            ai_table = make_detail_table(
                ai_rows
            )

            # -----------------------------------------------------
            # Findings
            # -----------------------------------------------------

            findings = risk.get(
                "findings"
            ) or []

            finding_flowables = [
                Paragraph(
                    "Security Findings",
                    subsection_style,
                )
            ]

            if findings:

                for finding in findings:

                    finding_flowables.append(
                        Paragraph(
                            f"• {display_value(finding_message(finding))}",
                            finding_style,
                        )
                    )

            else:

                finding_flowables.append(
                    Paragraph(
                        "No security findings recorded.",
                        note_style,
                    )
                )

            # -----------------------------------------------------
            # Recommendations
            # -----------------------------------------------------

            recommendations = risk.get(
                "recommendations"
            ) or []

            recommendation_flowables = [
                Paragraph(
                    "Recommended Actions",
                    subsection_style,
                )
            ]

            if recommendations:

                for recommendation in recommendations:

                    recommendation_flowables.append(
                        Paragraph(
                            f"• {display_value(recommendation)}",
                            recommendation_style,
                        )
                    )

            else:

                recommendation_flowables.append(
                    Paragraph(
                        "No remediation recommendations recorded.",
                        note_style,
                    )
                )

            # -----------------------------------------------------
            # Session block
            # -----------------------------------------------------

            session_block = [
                session_heading,
                make_section_banner(
                    "SECURITY POSTURE"
                ),
                posture_table,
                Spacer(
                    1,
                    5,
                ),
                make_section_banner(
                    "CERTIFICATE EVIDENCE"
                ),
                certificate_table,
                Spacer(
                    1,
                    5,
                ),
                make_section_banner(
                    "STARTTLS ANALYSIS"
                ),
                starttls_table,
                Spacer(
                    1,
                    5,
                ),
                make_section_banner(
                    "AI / ML INTELLIGENCE"
                ),
                ai_table,
                Spacer(
                    1,
                    5,
                ),
            ]

            story.append(
                KeepTogether(
                    session_block
                )
            )

            story.extend(
                finding_flowables
            )

            story.append(
                Spacer(
                    1,
                    3,
                )
            )

            story.extend(
                recommendation_flowables
            )

            story.append(
                Spacer(
                    1,
                    10,
                )
            )

        # =========================================================
        # METHODOLOGY
        # =========================================================

        story.append(
            Paragraph(
                "Assessment Methodology",
                section_style,
            )
        )

        methodology_text = (
            "SecureMailScope combines passive packet and session "
            "reconstruction with deterministic cryptographic rules "
            "and machine-learning intelligence. Deterministic "
            "analysis evaluates observed TLS versions, cipher "
            "suites, key exchange, certificate state, STARTTLS "
            "behavior and forward secrecy. The AI/ML layer "
            "classifies cryptographic risk and evaluates TLS "
            "behavior for anomalies. Where a handshake does not "
            "provide sufficient evidence, the framework reports "
            "the property as <b>Not determined</b> rather than "
            "inferring a security state."
        )

        story.append(
            Paragraph(
                methodology_text,
                body_style,
            )
        )

        story.append(
            Spacer(
                1,
                8,
            )
        )

        # =========================================================
        # REPORT CLOSING
        # =========================================================

        closing_table = Table(
            [
                [
                    Paragraph(
                        "<b>Evidence</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Risk</b>",
                        centered_small_style,
                    ),
                    Paragraph(
                        "<b>Action</b>",
                        centered_small_style,
                    ),
                ],
                [
                    Paragraph(
                        "Observed protocol, TLS and certificate evidence",
                        centered_small_style,
                    ),
                    Paragraph(
                        "Prioritized cryptographic security findings",
                        centered_small_style,
                    ),
                    Paragraph(
                        "Recommended remediation steps",
                        centered_small_style,
                    ),
                ],
            ],
            colWidths=[
                56.5 * mm,
                56.5 * mm,
                56.5 * mm,
            ],
            rowHeights=[
                9 * mm,
                15 * mm,
            ],
        )

        closing_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        DARK_RED,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "BACKGROUND",
                        (0, 1),
                        (-1, 1),
                        WARM_LIGHT,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        story.append(
            closing_table
        )

        story.append(
            Spacer(
                1,
                10,
            )
        )

        story.append(
            Paragraph(
                "SecureMailScope — AI-assisted cryptographic "
                "security posture assessment for secure email "
                "communications.",
                footer_style,
            )
        )

        # =========================================================
        # BUILD PDF
        # =========================================================

        document.build(
            story,
            onFirstPage=page_header_footer,
            onLaterPages=page_header_footer,
        )

        pdf_bytes = buffer.getvalue()

        buffer.close()

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    'attachment; '
                    'filename="securemailscope_report.pdf"'
                )
            },
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"PDF report generation failed: {error}"
            ),
        )
