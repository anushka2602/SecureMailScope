# SecureMailScope

### AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

SecureMailScope is a passive network forensic framework that analyzes captured SMTP, IMAP, and POP3 traffic to assess the cryptographic security posture of email communications.

It reconstructs email communication sessions from PCAP/PCAPNG files, analyzes TLS and STARTTLS behavior, extracts certificate information, detects cryptographic weaknesses, and combines rule-based security analysis with machine-learning-based risk classification and anomaly detection.

---

## 1. Problem Statement

Email is a critical communication mechanism for governments, enterprises, financial institutions, academic organizations, and other sensitive environments.

Although modern email systems commonly use TLS, insecure configurations can still expose communications to security risks. Examples include:

* Deprecated TLS versions
* Weak cipher suites
* CBC-mode encryption
* RSA key exchange without forward secrecy
* Insecure or missing STARTTLS upgrades
* Expired certificates
* Invalid certificate validity periods
* Weak certificate signature algorithms
* Weak public-key sizes
* Unusual TLS behavior

Traditional packet-analysis tools provide low-level network visibility, but they do not automatically produce an overall cryptographic security posture or intelligently prioritize the risks found in an email communication session.

SecureMailScope is designed to address this gap.

---

# 2. What SecureMailScope Does

SecureMailScope takes a captured network trace as input:

```text
PCAP / PCAPNG
      ↓
Email Protocol Identification
      ↓
TCP Stream Reconstruction
      ↓
TLS / STARTTLS Detection
      ↓
TLS Handshake Analysis
      ↓
Certificate Extraction & Analysis
      ↓
Cryptographic Feature Extraction
      ↓
Rule-Based Security Analysis
      ↓
ML Risk Classification
      ↓
TLS Anomaly Detection
      ↓
Security Posture
      ↓
Prioritized Findings & Recommendations
```

The goal is to transform raw network traffic into an understandable security assessment.

---

# 3. Key Features

## Passive PCAP Analysis

SecureMailScope does not need to actively connect to or scan an email server.

It works on captured network traffic.

Supported input formats:

* `.pcap`
* `.pcapng`

---

## Email Protocol Detection

The system identifies common email communication protocols based on network traffic and ports.

Supported protocols include:

| Protocol        | Common Port |
| --------------- | ----------: |
| SMTP            |          25 |
| SMTP Submission |         587 |
| SMTPS           |         465 |
| IMAP            |         143 |
| IMAPS           |         993 |
| POP3            |         110 |
| POP3S           |         995 |

---

## TCP Stream Reconstruction

The system reconstructs TCP streams from captured packets using TShark.

This allows SecureMailScope to analyze communication at the stream level rather than treating every packet independently.

---

## STARTTLS Analysis

SecureMailScope detects email protocols that support opportunistic TLS upgrades.

Examples:

* SMTP `STARTTLS`
* IMAP `STARTTLS`
* POP3 `STLS`

The system attempts to determine:

* Whether STARTTLS is supported
* Whether STARTTLS was requested
* Whether a TLS upgrade followed the request

---

## TLS Analysis

SecureMailScope analyzes TLS handshakes and extracts information such as:

* TLS version
* Negotiated cipher suite
* Supported cipher suites
* Handshake types
* Supported groups
* Key-exchange information
* Forward secrecy indicators

Currently recognized TLS versions include:

```text
SSL 3.0
TLS 1.0
TLS 1.1
TLS 1.2
TLS 1.3
```

---

## Certificate Analysis

When a certificate is observable in the captured TLS handshake, SecureMailScope extracts:

* Subject
* Issuer
* Serial number
* Valid-from date
* Valid-until date
* Expiration status
* Not-yet-valid status
* Public-key algorithm
* Public-key length
* Certificate signature algorithm
* Certificate version
* SHA-256 fingerprint

Example:

```text
Public Key: RSA
Key Size: 2048 bits
Signature: SHA-256
Status: Valid
```

### Important limitation

Certificate information is only available when the certificate is observable in the captured handshake.

For some TLS configurations, especially TLS 1.3 traffic, the amount of certificate information available to passive analysis may differ depending on the capture and handshake.

---

# 4. Security Rule Engine

SecureMailScope currently combines multiple security indicators into a security score from:

```text
0 = Best
100 = Worst
```

The rule engine evaluates factors such as:

* TLS version
* Cipher suite
* Public-key size
* Certificate expiration
* Certificate validity
* Certificate signature algorithm
* STARTTLS usage
* Forward secrecy

### Severity levels

|  Score | Severity |
| -----: | -------- |
|   0–29 | Low      |
|  30–59 | Medium   |
|  60–79 | High     |
| 80–100 | Critical |

The rule engine also produces human-readable recommendations for detected weaknesses.

---

# 5. Machine Learning

SecureMailScope uses machine learning as a complementary layer to deterministic security rules.

The project currently contains two ML components.

## Risk Classification

The risk classifier predicts a security risk category:

```text
Low
Medium
High
```

The classifier is trained using cryptographic security features such as:

* Protocol
* TLS version
* Cipher
* Key size
* Certificate status
* Signature algorithm
* STARTTLS
* Forward secrecy

The current risk classifier is based on XGBoost.

---

## TLS Anomaly Detection

An anomaly-detection model identifies TLS configurations that appear unusual compared with the learned baseline.

The current implementation uses an unsupervised anomaly-detection approach.

The result includes:

```text
is_anomaly
anomaly_score
```

---

# 6. Current ML Model Status

The current training dataset is synthetic.

It was generated to provide controlled combinations of email security configurations for initial model development and testing.

Therefore:

> ML performance reported by this project should currently be considered experimental and should not be interpreted as production-grade real-world accuracy.

The ML layer is intended to complement the deterministic security rules rather than replace them.

---

# 7. Current Test Case

A known insecure SMTP PCAP is included separately from the Git repository because captured network traffic is intentionally excluded from Git.

Test file:

```text
smtp_insecure_test.pcapng
```

The test traffic contains:

```text
TLS Version:
TLS 1.2

Cipher:
TLS_RSA_WITH_AES_256_CBC_SHA

Cipher ID:
0x0035

Forward Secrecy:
No
```

The current rule engine produces approximately:

```text
Security Score:
38 / 100

Severity:
Medium
```

Detected findings include:

```text
CBC-mode cipher suite detected.

Forward secrecy was not observed.
```

The ML layer currently classifies this example as:

```text
Risk:
Medium

Confidence:
~99.5%

Anomaly:
False
```

These values may change as the models and analysis pipeline are improved.

---

# 8. Project Structure

```text
SecureMailScope/
│
├── .gitignore
│
├── backend/
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   │
│   │   ├── analyzer/
│   │   │   ├── __init__.py
│   │   │   ├── pcap_parser.py
│   │   │   ├── protocol_detector.py
│   │   │   ├── email_sessions.py
│   │   │   ├── tls_analyzer.py
│   │   │   ├── certificate_analyzer.py
│   │   │   ├── starttls_analyzer.py
│   │   │   ├── tcp_reconstructor.py
│   │   │   ├── payload_decoder.py
│   │   │   └── feature_extractor.py
│   │   │
│   │   ├── security/
│   │   │   ├── __init__.py
│   │   │   ├── risk_engine.py
│   │   │   └── security_posture.py
│   │   │
│   │   ├── ml/
│   │   │   └── __init__.py
│   │   │
│   │   ├── reports/
│   │   │   └── __init__.py
│   │   │
│   │   └── api/
│   │       └── __init__.py
│   │
│   ├── data/
│   │   ├── raw/
│   │   ├── processed/
│   │   └── dataset/
│   │       ├── generate_dataset.py
│   │       └── email_crypto_dataset.csv
│   │
│   ├── ml/
│   │   ├── train_risk_model.py
│   │   ├── train_anomaly_model.py
│   │   └── test_ml_models.py
│   │
│   ├── models/
│   │   ├── risk_classifier.pkl
│   │   ├── risk_preprocessor.pkl
│   │   ├── risk_label_encoder.pkl
│   │   ├── tls_anomaly_detector.pkl
│   │   └── anomaly_preprocessor.pkl
│   │
│   ├── smtp_lab/
│   │   ├── generate_cert.py
│   │   ├── smtp_server.py
│   │   ├── smtp_client.py
│   │   ├── server.crt
│   │   └── server.key
│   │
│   └── requirements.txt
│
├── frontend/
│
├── pcaps/
│
└── scripts/
```

> `server.key`, PCAP files, and virtual environments are intentionally excluded from Git.

---

# 9. Technology Stack

## Backend

* Python
* FastAPI
* TShark
* PyShark
* Cryptography
* Pandas
* NumPy

## Machine Learning

* Scikit-learn
* XGBoost
* Joblib

## Network Analysis

* Wireshark
* TShark
* TCP stream reconstruction
* TLS handshake analysis

## Development

* Git
* GitHub
* VS Code / Cursor

---

# 10. Requirements

Recommended environment:

```text
Operating System:
Windows 10/11

Python:
3.14.x

Git:
Latest stable version

Wireshark:
Installed with TShark

VS Code or Cursor:
Recommended
```

TShark must be available from the command line.

Verify it with:

```powershell
tshark --version
```

---

# 11. Installation

## Step 1 — Clone the repository

```powershell
git clone https://github.com/anushka2602/SecureMailScope.git
```

Enter the project directory:

```powershell
cd SecureMailScope
```

---

## Step 2 — Create a virtual environment

```powershell
python -m venv backend\venv
```

Activate it:

```powershell
.\backend\venv\Scripts\Activate.ps1
```

Your terminal should now show something similar to:

```text
(venv) PS C:\Users\<username>\Documents\SecureMailScope>
```

---

## Step 3 — Install dependencies

```powershell
pip install -r backend\requirements.txt
```

---

# 12. Running the Backend

From the project root, activate the virtual environment:

```powershell
.\backend\venv\Scripts\Activate.ps1
```

Move into the backend:

```powershell
cd backend
```

Start FastAPI:

```powershell
uvicorn app.main:app --reload
```

The API should become available at:

```text
http://127.0.0.1:8000
```

Swagger API documentation:

```text
http://127.0.0.1:8000/docs
```

---

# 13. API Endpoints

## GET `/`

Returns basic project information.

Example:

```json
{
  "project": "SecureMailScope",
  "status": "running",
  "version": "0.1.0"
}
```

---

## GET `/health`

Health-check endpoint.

Example:

```json
{
  "status": "healthy"
}
```

---

## POST `/analyze`

Accepts a:

```text
.pcap
.pcapng
```

file and performs the complete analysis pipeline.

The response contains:

* Filename
* Number of sessions
* Protocol
* Extracted features
* TLS analysis
* STARTTLS analysis
* Certificate information
* ML risk prediction
* Anomaly detection
* Security score
* Severity
* Findings
* Recommendations

---

# 14. Testing a PCAP

Place the test PCAP inside:

```text
SecureMailScope/
└── pcaps/
    └── smtp_insecure_test.pcapng
```

Start the backend:

```powershell
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

Select:

```text
POST /analyze
```

Click:

```text
Try it out
```

Upload the PCAP and execute the request.

The API should return the complete security analysis.

---

# 15. SMTP Test Lab

SecureMailScope contains a small SMTP laboratory for generating controlled email/TLS traffic.

The lab contains:

```text
backend/smtp_lab/
├── generate_cert.py
├── smtp_server.py
├── smtp_client.py
└── server.crt
```

The lab can be used to generate traffic that can then be captured with Wireshark and analyzed by SecureMailScope.

This is useful for creating controlled:

* Secure TLS traffic
* Weak cipher traffic
* STARTTLS traffic
* Different TLS configurations
* Certificate test cases

---

# 16. Creating Test PCAPs

A typical workflow is:

```text
SMTP Client
     ↓
SMTP Test Server
     ↓
Wireshark Capture
     ↓
PCAP / PCAPNG
     ↓
SecureMailScope
     ↓
Security Assessment
```

For local SMTP testing, Wireshark can capture traffic on the Npcap Loopback Adapter.

Example display filter:

```text
tcp.port == 2525
```

Save the resulting capture as:

```text
.pcapng
```

Then analyze it using SecureMailScope.

---

# 17. Security Considerations

This project works with network captures.

PCAP files may contain sensitive information such as:

* IP addresses
* Email metadata
* Email contents
* Authentication information
* TLS handshake information
* Other network traffic

Therefore:

**Never commit sensitive PCAP files to GitHub.**

The repository's `.gitignore` excludes:

```text
*.pcap
*.pcapng
*.cap
```

Private TLS keys are also excluded:

```text
*.key
*.pem
```

Virtual environments are excluded as well.

---

# 18. What Should NOT Be Committed

Do not commit:

```text
backend/venv/

*.pcap
*.pcapng
*.cap

server.key
*.key
*.pem

.env
.env.*

reports/
*.pdf
*.html
```

If a file contains credentials, private keys, secrets, or sensitive network captures, do not commit it.

---

# 19. Development Workflow

All team members should work through Git.

Before starting work:

```powershell
git pull origin main
```

Create a feature branch:

```powershell
git checkout -b feature/<feature-name>
```

Example:

```powershell
git checkout -b feature/dashboard
```

After making changes:

```powershell
git status
```

Stage changes:

```powershell
git add .
```

Commit:

```powershell
git commit -m "Add dashboard analysis view"
```

Push:

```powershell
git push -u origin feature/dashboard
```

Then create a Pull Request on GitHub.

---

# 20. Recommended Team Workflow

Avoid having multiple people directly modify the same files whenever possible.

Example division:

```text
Team Member 1
→ Frontend / Dashboard

Team Member 2
→ PCAP / TLS Analysis

Team Member 3
→ ML / Risk Classification

Team Member 4
→ Reports / Integration / Testing
```

Coordinate changes before modifying core files such as:

```text
main.py
feature_extractor.py
security_posture.py
```

---

# 21. Current Architecture

```text
                    ┌──────────────────────┐
                    │      PCAP / PCAPNG   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Email Protocol       │
                    │ Identification       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ TCP Stream           │
                    │ Reconstruction       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ TLS / STARTTLS       │
                    │ Analysis             │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴───────────┐
                    │                      │
                    ▼                      ▼
          ┌─────────────────┐    ┌──────────────────┐
          │ TLS Handshake   │    │ X.509 Certificate│
          │ Analysis        │    │ Analysis         │
          └────────┬────────┘    └────────┬─────────┘
                   │                      │
                   └──────────┬───────────┘
                              ▼
                    ┌──────────────────────┐
                    │ Cryptographic        │
                    │ Feature Extraction   │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
       ┌────────────────────┐     ┌────────────────────┐
       │ Rule-Based         │     │ Machine Learning   │
       │ Security Engine    │     │ Risk Analysis      │
       └──────────┬─────────┘     └──────────┬─────────┘
                  │                          │
                  └────────────┬─────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Security Posture     │
                    │ Assessment           │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Findings             │
                    │ Risk Score           │
                    │ Recommendations      │
                    │ Anomalies             │
                    └──────────────────────┘
```

---

# 22. Design Philosophy

SecureMailScope follows the principle:

> **Observe → Analyze → Assess → Explain**

The system is designed to be passive and forensic rather than an active vulnerability scanner.

Instead of simply saying:

```text
TLS detected
```

the goal is to answer:

```text
What TLS configuration was used?

Is the configuration secure?

What cryptographic weaknesses exist?

How severe are they?

Is the behavior anomalous?

What should the administrator do about it?
```

---

# 23. Current Limitations

SecureMailScope is currently a research/prototype implementation.

Known limitations include:

### Passive Visibility

Some information cannot be recovered if it was not visible in the captured traffic.

### TLS 1.3

TLS 1.3 changes the visibility of certain handshake information compared with older TLS versions.

### Certificate Validation

The current certificate analyzer extracts and evaluates certificate properties from observed certificates. Full production-grade PKI path validation is a future enhancement.

### STARTTLS Detection

STARTTLS detection depends on visible application-layer payloads in the capture.

### ML Dataset

The current ML dataset is synthetic and therefore does not represent the full diversity of real-world email infrastructure.

### ML Generalization

The current models should not be treated as production-ready security classifiers.

---

# 24. Future Improvements

Planned improvements include:

* Full SMTP/IMAP/POP3 session reconstruction
* Better STARTTLS downgrade detection
* More complete TLS handshake reconstruction
* Certificate-chain validation
* Hostname/SAN validation
* OCSP/CRL analysis where applicable
* More comprehensive cipher-suite evaluation
* JA3/JA4-style TLS fingerprinting
* Better anomaly detection
* Real-world labeled datasets
* Explainable ML risk classification
* Risk prioritization across multiple sessions
* Security posture dashboards
* HTML reports
* PDF reports
* JSON export
* Session comparison
* Historical security posture tracking
* Enterprise/SOC integration

---

# 25. SIH Alignment

SecureMailScope directly addresses the requirements of the SIH problem statement by providing:

| Requirement                   | Implementation                     |
| ----------------------------- | ---------------------------------- |
| Passive PCAP analysis         | PCAP/PCAPNG pipeline               |
| Email protocol identification | SMTP/IMAP/POP3 detection           |
| STARTTLS analysis             | STARTTLS/STLS analyzer             |
| TCP reconstruction            | TShark-based stream reconstruction |
| TLS analysis                  | TLS handshake analyzer             |
| Certificate analysis          | X.509 analyzer                     |
| Weak crypto detection         | Rule engine                        |
| Security posture              | Security scoring                   |
| AI/ML risk classification     | XGBoost classifier                 |
| Anomaly detection             | ML anomaly detector                |
| Risk prioritization           | Risk/severity output               |
| Recommendations               | Rule-based recommendations         |
| Forensic workflow             | Passive network analysis           |

---

# 26. Project Status

### Current status

```text
[✓] Project repository
[✓] Git/GitHub setup
[✓] FastAPI backend
[✓] PCAP parsing
[✓] Email protocol detection
[✓] TCP stream reconstruction
[✓] Payload decoding
[✓] STARTTLS analysis
[✓] TLS analysis
[✓] Certificate extraction
[✓] Certificate analysis
[✓] Rule-based security scoring
[✓] ML risk classifier
[✓] TLS anomaly detector
[✓] SMTP test laboratory
[✓] Insecure SMTP PCAP test
[ ] Frontend dashboard
[ ] Advanced reporting
[ ] Complete certificate-chain validation
[ ] Expanded real-world dataset
[ ] Production-grade ML validation
```

---

# 27. Repository

GitHub:

https://github.com/anushka2602/SecureMailScope

---

# 28. Team Note

When contributing to SecureMailScope:

1. Pull the latest `main` branch before starting.
2. Create a feature branch.
3. Keep changes focused.
4. Test your changes locally.
5. Never commit PCAPs, private keys, credentials, or virtual environments.
6. Commit with a meaningful message.
7. Push your branch.
8. Create a Pull Request.
9. Review changes before merging into `main`.

The `main` branch should remain in a working state.

---

## SecureMailScope

**Detect cryptographic weaknesses. Understand their impact. Prioritize the risk. Explain how to fix it.**
