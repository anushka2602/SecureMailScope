import { useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileSearch,
  Fingerprint,
  LockKeyhole,
  Network,
  Shield,
  ShieldAlert,
  Upload,
} from "lucide-react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const openFilePicker = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    setSelectedFile(file);
    setError("");
    setAnalysis(null);
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "PCAP analysis failed.");
      }

      setAnalysis(data);
    } catch (err) {
      setAnalysis(null);
      setError(
        err.message ||
          "Unable to connect to the SecureMailScope analysis engine."
      );
    } finally {
      setLoading(false);
    }
  };

  const session = analysis?.sessions?.[0];
  const features = session?.features;
  const posture = session?.posture;
  const certificate = session?.certificate;
  const tls = session?.tls;
  const starttls = session?.starttls;

  const riskLabel = posture?.risk?.label || "Unknown";

  const riskConfidence = posture?.risk?.confidence
    ? `${(posture.risk.confidence * 100).toFixed(2)}%`
    : "—";

  const score = posture?.security?.score ?? 0;

  const scoreClass =
    score >= 70
      ? "score-good"
      : score >= 40
        ? "score-warning"
        : "score-danger";

  const tlsVersion =
    tls?.negotiated_tls_version ||
    features?.tls_version ||
    "Not detected";

  const cipher =
    tls?.negotiated_cipher_suite ||
    features?.cipher ||
    "Not detected";

  const keyExchange =
    tls?.key_exchange ||
    features?.key_exchange ||
    "Not detected";

  const keySize =
    certificate?.public_key_length ||
    features?.key_size ||
    "Not detected";

  const starttlsDetected =
    starttls?.tls_upgrade_detected === true ||
    features?.starttls === 1;

  const forwardSecrecy =
    tls?.forward_secrecy === true ||
    features?.forward_secrecy === 1;

  const certificateValid =
    certificate?.certificate_present &&
    !certificate?.expired &&
    !certificate?.not_yet_valid;

  const findings = posture?.findings || [];
  const recommendations = posture?.recommendations || [];

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <div className="ambient ambient-three" />

      <div className="background-grid" />
      <div className="background-scanline" />

      <aside className="sidebar glass-panel">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={18} />
          </div>

          <div className="brand-text">
            <strong>SecureMailScope</strong>
            <span>Cryptographic Security</span>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-title">WORKSPACE</div>

          <button className="nav-item active">
            <Shield size={15} />
            <span>Security Overview</span>
          </button>

          <button className="nav-item">
            <FileSearch size={15} />
            <span>PCAP Analysis</span>
          </button>

          <button className="nav-item">
            <Network size={15} />
            <span>Network Sessions</span>
          </button>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-title">ANALYSIS</div>

          <button className="nav-item">
            <LockKeyhole size={15} />
            <span>TLS Security</span>
          </button>

          <button className="nav-item">
            <Fingerprint size={15} />
            <span>Certificates</span>
          </button>
        </div>

        <div className="sidebar-bottom">
          <div className="engine-status">
            <div className="status-dot" />

            <div>
              <strong>Analysis Engine</strong>
              <span>Operational</span>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar glass-bar">
          <div className="topbar-title">
            SECURITY OPERATIONS
          </div>

          <div className="topbar-right">
            <div className="operational-badge">
              <span className="status-dot" />
              Operational
            </div>

            <div className="version-badge">
              SecureMailScope v0.1.0
            </div>
          </div>
        </header>

        <div className="page">
          <div className="page-heading">
            <div className="heading-kicker">
              <span className="kicker-line" />
              PASSIVE NETWORK FORENSICS
            </div>

            <h1>Security Overview</h1>

            <p>
              Analyze email traffic and identify cryptographic weaknesses from
              passive network captures.
            </p>
          </div>

          <section className="upload-panel glass-featured">
            <div className="upload-glow" />

            <div className="upload-content">
              <div className="upload-copy">
                <div className="upload-icon">
                  <Upload size={23} />
                </div>

                <div className="upload-copy-text">
                  <div className="micro-label">
                    CAPTURE ANALYSIS
                  </div>

                  <h2>Analyze a network capture</h2>

                  <p>
                    Upload a PCAP or PCAPNG file containing SMTP, IMAP, or POP3
                    traffic.
                  </p>
                </div>
              </div>

              <div className="upload-actions">
                <button
                  className="upload-button"
                  onClick={openFilePicker}
                  disabled={loading}
                >
                  <Upload size={14} />

                  {loading ? "Analyzing..." : "Upload PCAP"}

                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pcap,.pcapng"
                    onChange={handleFileChange}
                  />
                </button>
              </div>
            </div>

            <div className="upload-decoration">
              <span />
              <span />
              <span />
              <span />
              <span />
            </div>
          </section>

          {error && (
            <div className="error-panel glass-panel">
              <AlertTriangle size={17} />

              <div>
                <strong>Analysis failed</strong>
                <span>{error}</span>
              </div>
            </div>
          )}

          {!analysis && !loading && !error && (
            <section className="empty-state glass-panel">
              <div className="empty-orbit">
                <div className="empty-icon">
                  <FileSearch size={25} />
                </div>
              </div>

              <div className="empty-kicker">
                READY FOR CAPTURE
              </div>

              <h2>No PCAP analyzed yet</h2>

              <p>
                Upload a network capture to begin cryptographic security
                assessment.
              </p>

              <button
                className="empty-button"
                onClick={openFilePicker}
              >
                <Upload size={13} />
                Upload your first PCAP
                <ArrowRight size={13} />
              </button>
            </section>
          )}

          {loading && (
            <section className="empty-state loading-state glass-panel">
              <div className="analysis-loader">
                <div className="loader-ring">
                  <Activity size={24} />
                </div>

                <span className="loader-orbit orbit-one" />
                <span className="loader-orbit orbit-two" />
              </div>

              <div className="empty-kicker">
                ANALYSIS ENGINE ACTIVE
              </div>

              <h2>Analyzing network capture</h2>

              <p>
                Reconstructing sessions, inspecting TLS and evaluating
                cryptographic security.
              </p>

              <div className="loading-progress">
                <span />
              </div>
            </section>
          )}

          {analysis && session && (
            <>
              <div className="analysis-meta glass-panel">
                <div>
                  <span>Capture</span>
                  <strong title={analysis.filename}>
                    {analysis.filename}
                  </strong>
                </div>

                <div>
                  <span>Sessions detected</span>
                  <strong>{analysis.session_count}</strong>
                </div>

                <div>
                  <span>Protocol</span>
                  <strong>{session.protocol}</strong>
                </div>

                <div>
                  <span>TCP stream</span>
                  <strong>#{session.stream_id}</strong>
                </div>
              </div>

              <div className="overview-grid">
                <section
                  className={`card score-card glass-panel ${scoreClass}`}
                >
                  <div className="score-card-inner">
                    <div
                      className="score-ring"
                      style={{
                        "--score-angle": `${score * 3.6}deg`,
                      }}
                    >
                      <div className="score-ring-glow" />

                      <div className="score-value">
                        <strong>{score}</strong>
                        <span>Security score</span>
                      </div>
                    </div>

                    <div className="score-details">
                      <div className="section-eyebrow">
                        RULE-BASED ASSESSMENT
                      </div>

                      <h2>
                        {posture?.security?.severity || "Unknown"} Risk
                      </h2>

                      <p>
                        Cryptographic configuration analyzed against
                        SecureMailScope security rules.
                      </p>

                      <span className={`badge ${scoreClass}`}>
                        {score >= 70
                          ? "Secure"
                          : score >= 40
                            ? "Needs attention"
                            : "Weak configuration"}
                      </span>
                    </div>
                  </div>
                </section>

                <div className="metric-grid">
                  <div className="metric-card glass-panel">
                    <div className="metric-top">
                      <span className="metric-label">
                        TLS Version
                      </span>

                      <LockKeyhole
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div className="metric-value">
                      {tlsVersion}
                    </div>

                    <div className="metric-sub">
                      Negotiated protocol version
                    </div>
                  </div>

                  <div className="metric-card glass-panel">
                    <div className="metric-top">
                      <span className="metric-label">
                        Cipher Suite
                      </span>

                      <Shield
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div className="metric-value">
                      {cipher.replace("TLS_RSA_WITH_", "")}
                    </div>

                    <div className="metric-sub">
                      {cipher}
                    </div>
                  </div>

                  <div className="metric-card glass-panel">
                    <div className="metric-top">
                      <span className="metric-label">
                        Key Exchange
                      </span>

                      <Network
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div className="metric-value">
                      {keyExchange}
                    </div>

                    <div className="metric-sub">
                      Forward secrecy:{" "}
                      {forwardSecrecy ? "Yes" : "No"}
                    </div>
                  </div>

                  <div className="metric-card glass-panel">
                    <div className="metric-top">
                      <span className="metric-label">
                        Certificate
                      </span>

                      <Fingerprint
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div
                      className={`metric-value ${
                        certificateValid
                          ? "good-text"
                          : "bad-text"
                      }`}
                    >
                      {certificateValid
                        ? "Valid"
                        : "Issue detected"}
                    </div>

                    <div className="metric-sub">
                      {certificate?.public_key_algorithm ||
                        "Unknown"}{" "}
                      {keySize}
                    </div>
                  </div>
                </div>
              </div>

              <div className="section-grid">
                <section className="card glass-panel">
                  <div className="card-header">
                    <div>
                      <div className="section-eyebrow">
                        CRYPTOGRAPHIC ANALYSIS
                      </div>

                      <h3>Security Configuration</h3>
                    </div>

                    <LockKeyhole size={15} />
                  </div>

                  <div className="config-list">
                    <ConfigRow
                      label="Protocol"
                      value={
                        features?.protocol ||
                        session.protocol
                      }
                    />

                    <ConfigRow
                      label="Negotiated TLS"
                      value={tlsVersion}
                      valueClass={
                        tlsVersion === "TLS 1.3"
                          ? "good"
                          : tlsVersion === "TLS 1.2"
                            ? "warning"
                            : "bad"
                      }
                    />

                    <ConfigRow
                      label="Cipher suite"
                      value={cipher}
                      valueClass={
                        cipher.includes("CBC")
                          ? "bad"
                          : "good"
                      }
                    />

                    <ConfigRow
                      label="Key exchange"
                      value={keyExchange}
                      valueClass={
                        keyExchange === "RSA"
                          ? "bad"
                          : "good"
                      }
                    />

                    <ConfigRow
                      label="Public key"
                      value={`${certificate?.public_key_algorithm || "Unknown"} ${keySize}`}
                    />

                    <ConfigRow
                      label="Certificate signature"
                      value={
                        certificate?.signature_algorithm ||
                        "Unknown"
                      }
                      valueClass={
                        certificate?.signature_algorithm
                          ?.toLowerCase()
                          .includes("sha1")
                          ? "bad"
                          : "good"
                      }
                    />
                  </div>
                </section>

                <section className="card glass-panel">
                  <div className="card-header">
                    <div>
                      <div className="section-eyebrow">
                        TRANSPORT SECURITY
                      </div>

                      <h3>TLS & STARTTLS Posture</h3>
                    </div>

                    <Activity size={15} />
                  </div>

                  <div className="config-list">
                    <ConfigRow
                      label="STARTTLS advertised"
                      value={
                        starttls?.starttls_supported
                          ? "Detected"
                          : "Not detected"
                      }
                      valueClass={
                        starttls?.starttls_supported
                          ? "good"
                          : "bad"
                      }
                    />

                    <ConfigRow
                      label="STARTTLS requested"
                      value={
                        starttls?.starttls_requested
                          ? "Yes"
                          : "No"
                      }
                      valueClass={
                        starttls?.starttls_requested
                          ? "good"
                          : "bad"
                      }
                    />

                    <ConfigRow
                      label="TLS upgrade"
                      value={
                        starttlsDetected
                          ? "Successfully detected"
                          : "Not detected"
                      }
                      valueClass={
                        starttlsDetected
                          ? "good"
                          : "bad"
                      }
                    />

                    <ConfigRow
                      label="Forward secrecy"
                      value={
                        forwardSecrecy
                          ? "Enabled"
                          : "Not provided"
                      }
                      valueClass={
                        forwardSecrecy
                          ? "good"
                          : "bad"
                      }
                    />

                    <ConfigRow
                      label="Certificate validity"
                      value={
                        certificateValid
                          ? "Currently valid"
                          : "Invalid / unavailable"
                      }
                      valueClass={
                        certificateValid
                          ? "good"
                          : "bad"
                      }
                    />

                    <ConfigRow
                      label="Anomaly detection"
                      value={
                        posture?.anomaly?.is_anomaly
                          ? "Anomaly detected"
                          : "No anomaly"
                      }
                      valueClass={
                        posture?.anomaly?.is_anomaly
                          ? "bad"
                          : "good"
                      }
                    />
                  </div>
                </section>
              </div>

              <section className="card ai-card glass-panel">
                <div className="card-header">
                  <div>
                    <div className="section-eyebrow">
                      MACHINE LEARNING
                    </div>

                    <h3>AI Security Assessment</h3>
                  </div>

                  <ShieldAlert size={15} />
                </div>

                <div className="ai-content">
                  <div className="ai-summary">
                    <div className="ai-risk">
                      <div className="ai-icon">
                        <Activity size={18} />
                      </div>

                      <div>
                        <strong>{riskLabel} Risk</strong>

                        <span>
                          ML classification confidence:{" "}
                          {riskConfidence}
                        </span>
                      </div>
                    </div>

                    <div className="confidence">
                      <div className="confidence-head">
                        <span>Confidence</span>

                        <strong>{riskConfidence}</strong>
                      </div>

                      <div className="confidence-bar">
                        <span
                          style={{
                            width: `${
                              (posture?.risk?.confidence || 0) *
                              100
                            }%`,
                          }}
                        />
                      </div>
                    </div>

                    <div
                      className={`anomaly-status ${
                        posture?.anomaly?.is_anomaly
                          ? "anomaly"
                          : ""
                      }`}
                    >
                      {posture?.anomaly?.is_anomaly ? (
                        <AlertTriangle size={13} />
                      ) : (
                        <CheckCircle2 size={13} />
                      )}

                      <span>
                        {posture?.anomaly?.is_anomaly
                          ? "TLS anomaly detected"
                          : "No anomalous TLS behavior"}
                      </span>
                    </div>
                  </div>
                </div>
              </section>

              <div className="section-grid">
                <section className="card glass-panel">
                  <div className="card-header">
                    <div>
                      <div className="section-eyebrow">
                        FORENSIC FINDINGS
                      </div>

                      <h3>Security Findings</h3>
                    </div>

                    <AlertTriangle size={15} />
                  </div>

                  <div className="findings-list">
                    {findings.length === 0 ? (
                      <div className="no-findings">
                        <CheckCircle2 size={15} />
                        No security findings detected.
                      </div>
                    ) : (
                      findings.map((finding, index) => (
                        <div
                          className="finding"
                          key={index}
                        >
                          <div className="finding-icon">
                            <AlertTriangle size={14} />
                          </div>

                          <div className="finding-content">
                            <strong>
                              Security weakness detected
                            </strong>

                            <p>{finding}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </section>

                <section className="card glass-panel">
                  <div className="card-header">
                    <div>
                      <div className="section-eyebrow">
                        REMEDIATION
                      </div>

                      <h3>Recommendations</h3>
                    </div>

                    <ArrowRight size={15} />
                  </div>

                  <div className="recommendation-list">
                    {recommendations.length === 0 ? (
                      <div className="no-findings">
                        <CheckCircle2 size={15} />
                        No recommendations required.
                      </div>
                    ) : (
                      recommendations.map(
                        (recommendation, index) => (
                          <div
                            className="recommendation"
                            key={index}
                          >
                            <div className="recommendation-number">
                              {String(index + 1).padStart(
                                2,
                                "0"
                              )}
                            </div>

                            <p>{recommendation}</p>
                          </div>
                        )
                      )
                    )}
                  </div>
                </section>
              </div>

              <div className="analysis-footer">
                <span>
                  Passive network forensic analysis • No traffic
                  modification
                </span>

                <strong>
                  {analysis.session_count} email session
                  {analysis.session_count === 1 ? "" : "s"}{" "}
                  analyzed
                </strong>
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function ConfigRow({
  label,
  value,
  valueClass = "",
}) {
  return (
    <div className="config-row">
      <span className="config-label">
        {label}
      </span>

      <strong className={`config-value ${valueClass}`}>
        {value}
      </strong>
    </div>
  );
}

export default App;