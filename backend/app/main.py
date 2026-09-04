from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, UploadFile, HTTPException

from app.analyzer.feature_extractor import extract_features_from_pcap
from app.security.security_posture import analyze_security_posture


app = FastAPI(
    title="SecureMailScope",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "SecureMailScope",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Analyze an uploaded PCAP/PCAPNG file and return
    the cryptographic security posture.
    """

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    allowed_extensions = {
        ".pcap",
        ".pcapng",
    }

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

            shutil.copyfileobj(
                file.file,
                temp_file,
            )

        sessions = extract_features_from_pcap(
            str(temp_path)
        )

        if not sessions:
            raise HTTPException(
                status_code=422,
                detail="No SMTP, IMAP, or POP3 sessions were detected in the PCAP.",
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

        return {
            "filename": file.filename,
            "session_count": len(analyzed_sessions),
            "sessions": analyzed_sessions,
        }

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