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

function getSeverityClass(severity) {
  if (severity === "Critical" || severity === "High") {
    return "danger";
  }

  if (severity === "Medium") {
    return "warning";
  }

  return "success";
}

function getScoreClass(severity) {
  if (severity === "Critical" || severity === "High") {
    return "score-danger";
  }

  if (severity === "Medium") {
    return "score-warning";
  }

  return "score-good";
}

function getSeverityLabel(severity) {
  switch (severity) {
    case "Critical":
      return "Critical risk";
    case "High":
      return "High risk";
    case "Medium":
      return "Needs attention";
    case "Low":
      return "Secure";
    default:
      return "Unknown";
  }
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function App() {
  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [selectedSessionIndex, setSelectedSessionIndex] =
    useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const openFilePicker = () => {
    fileInputRef.current?.click();
  };

  const scrollToSection = (id) => {
    document.getElementById(id)?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  };

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    const extension = file.name
      .toLowerCase()
      .split(".")
      .pop();

    if (!["pcap", "pcapng"].includes(extension)) {
      setSelectedFile(null);
      setAnalysis(null);
      setError("Please select a .pcap or .pcapng file.");
      setLoading(false);

      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }

      return;
    }

    setSelectedFile(file);
    setError("");
    setAnalysis(null);
    setSelectedSessionIndex(0);
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        body: formData,
      });

      let data;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          "The analysis engine returned an invalid response."
        );
      }

      if (!response.ok) {
        throw new Error(
          data?.detail || "PCAP analysis failed."
        );
      }

      if (
        !Array.isArray(data?.sessions) ||
        data.sessions.length === 0
      ) {
        throw new Error(
          "No email sessions were detected in this capture."
        );
      }

      setAnalysis(data);
      setSelectedSessionIndex(0);
    } catch (err) {
      setAnalysis(null);

      if (
        err instanceof TypeError &&
        err.message.toLowerCase().includes("fetch")
      ) {
        setError(
          "Unable to connect to the SecureMailScope analysis engine. Make sure the backend is running on port 8000."
        );
      } else {
        setError(
          err?.message ||
            "Unable to connect to the SecureMailScope analysis engine."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  const sessions = Array.isArray(analysis?.sessions)
    ? analysis.sessions
    : [];

  const safeSelectedSessionIndex =
    selectedSessionIndex >= 0 &&
    selectedSessionIndex < sessions.length
      ? selectedSessionIndex
      : 0;

  const session =
    sessions[safeSelectedSessionIndex] || null;

  const features = session?.features || {};
  const posture = session?.posture || {};
  const certificate = session?.certificate || {};
  const tls = session?.tls || {};
  const starttls = session?.starttls || {};

  const riskLabel = posture?.risk?.label || "Unknown";

  const rawConfidence =
    typeof posture?.risk?.confidence === "number"
      ? posture.risk.confidence
      : 0;

  const confidence = clamp(rawConfidence, 0, 1);

  const riskConfidence =
    typeof posture?.risk?.confidence === "number"
      ? `${(confidence * 100).toFixed(2)}%`
      : "—";

  const rawScore =
    typeof posture?.security?.score === "number"
      ? posture.security.score
      : 0;

  const score = clamp(rawScore, 0, 100);

  const securitySeverity =
    posture?.security?.severity || "Unknown";

  const scoreClass =
    getScoreClass(securitySeverity);

  const severityLabel =
    getSeverityLabel(securitySeverity);

  const tlsDetected =
    tls?.tls_detected === true;

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

  const forwardSecrecyLabel = !tlsDetected
    ? "Not applicable"
    : forwardSecrecy
      ? "Yes"
      : "No";

  const certificatePresent =
    certificate?.certificate_present === true;

  const certificateValid =
    certificatePresent &&
    certificate?.expired !== true &&
    certificate?.not_yet_valid !== true;

  const findings = Array.isArray(posture?.findings)
    ? posture.findings
    : [];

  const recommendations = Array.isArray(
    posture?.recommendations
  )
    ? posture.recommendations
    : [];

  const riskCounts = sessions.reduce(
    (counts, currentSession) => {
      const severity =
        currentSession?.posture?.security?.severity;

      if (severity === "Low") {
        counts.low += 1;
      } else if (severity === "Medium") {
        counts.medium += 1;
      } else if (severity === "High") {
        counts.high += 1;
      } else if (severity === "Critical") {
        counts.critical += 1;
      }

      return counts;
    },
    {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    }
  );

  const protocolCounts = sessions.reduce(
    (counts, currentSession) => {
      const protocol =
        currentSession?.protocol || "Unknown";

      counts[protocol] =
        (counts[protocol] || 0) + 1;

      return counts;
    },
    {}
  );

  const tlsCount = sessions.filter(
    (currentSession) =>
      currentSession?.tls?.tls_detected === true
  ).length;

  const anomalyCount = sessions.filter(
    (currentSession) =>
      currentSession?.posture?.anomaly
        ?.is_anomaly === true
  ).length;

  const certificateIssueCount = sessions.filter(
    (currentSession) => {
      const cert = currentSession?.certificate;

      return (
        cert?.certificate_present === true &&
        (cert?.expired === true ||
          cert?.not_yet_valid === true)
      );
    }
  ).length;

  const getSessionTitle = (
    currentSession,
    index
  ) => {
    const protocol =
      currentSession?.protocol || "Unknown";

    const streamId =
      currentSession?.stream_id ?? index;

    return `${protocol} • Stream #${streamId}`;
  };

  const getCipherDisplayName = (value) => {
    if (!value || value === "Not detected") {
      return "Not detected";
    }

    return value
      .replace("TLS_RSA_WITH_", "")
      .replace("TLS_ECDHE_RSA_WITH_", "");
  };

  const getCertificateDisplay = () => {
    if (!certificatePresent) {
      return "No certificate observed";
    }

    return `${certificate?.public_key_algorithm || "Unknown"} ${keySize}`;
  };

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
          <div className="sidebar-section-title">
            WORKSPACE
          </div>

          <button
            className="nav-item active"
            onClick={() =>
              scrollToSection("security-overview")
            }
          >
            <Shield size={15} />
            <span>Security Overview</span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection("capture-analysis")
            }
          >
            <FileSearch size={15} />
            <span>PCAP Analysis</span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection("network-sessions")
            }
          >
            <Network size={15} />
            <span>Network Sessions</span>
          </button>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-title">
            ANALYSIS
          </div>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection("tls-analysis")
            }
          >
            <LockKeyhole size={15} />
            <span>TLS Security</span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection("certificate-analysis")
            }
          >
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
          <div
            className="page-heading"
            id="security-overview"
          >
            <div className="heading-kicker">
              <span className="kicker-line" />
              PASSIVE NETWORK FORENSICS
            </div>

            <h1>Security Overview</h1>

            <p>
              Analyze email traffic and identify
              cryptographic weaknesses from passive
              network captures.
            </p>
          </div>

          <section
            className="upload-panel glass-featured"
            id="capture-analysis"
          >
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

                  <h2>
                    Analyze a network capture
                  </h2>

                  <p>
                    Upload a PCAP or PCAPNG file
                    containing SMTP, IMAP, or POP3
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

                  {loading
                    ? "Analyzing..."
                    : "Upload PCAP"}

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

          {selectedFile &&
            !loading &&
            !error &&
            !analysis && (
              <div className="analysis-meta glass-panel">
                <div>
                  <span>Capture</span>

                  <strong title={selectedFile.name}>
                    {selectedFile.name}
                  </strong>
                </div>

                <div>
                  <span>Status</span>
                  <strong>Ready</strong>
                </div>
              </div>
            )}

          {error && (
            <div className="error-panel glass-panel">
              <AlertTriangle size={17} />

              <div>
                <strong>Analysis failed</strong>
                <span>{error}</span>
              </div>
            </div>
          )}

          {!analysis &&
            !loading &&
            !error && (
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
                  Upload a network capture to begin
                  cryptographic security assessment.
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

              <h2>
                Analyzing network capture
              </h2>

              <p>
                Reconstructing sessions, inspecting
                TLS and evaluating cryptographic
                security.
              </p>

              <div className="loading-progress">
                <span />
              </div>
            </section>
          )}

          {analysis && (
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
                  <strong>
                    {analysis.session_count ??
                      sessions.length}
                  </strong>
                </div>

                <div>
                  <span>TLS sessions</span>
                  <strong>{tlsCount}</strong>
                </div>

                <div>
                  <span>Analyzed</span>
                  <strong>Complete</strong>
                </div>
              </div>

              <section className="card glass-panel">
                <div className="card-header">
                  <div>
                    <div className="section-eyebrow">
                      CAPTURE SUMMARY
                    </div>

                    <h3>
                      Security Posture Overview
                    </h3>
                  </div>

                  <Shield size={15} />
                </div>

                <div className="metric-grid">
                  <div className="metric-card">
                    <div className="metric-top">
                      <span className="metric-label">
                        Total Sessions
                      </span>

                      <Network
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div className="metric-value">
                      {sessions.length}
                    </div>

                    <div className="metric-sub">
                      Email sessions reconstructed
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="metric-top">
                      <span className="metric-label">
                        Low Risk
                      </span>

                      <CheckCircle2
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div className="metric-value good-text">
                      {riskCounts.low}
                    </div>

                    <div className="metric-sub">
                      Secure configurations
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="metric-top">
                      <span className="metric-label">
                        Medium Risk
                      </span>

                      <AlertTriangle
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div className="metric-value">
                      {riskCounts.medium}
                    </div>

                    <div className="metric-sub">
                      Configurations needing
                      attention
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="metric-top">
                      <span className="metric-label">
                        TLS Anomalies
                      </span>

                      <ShieldAlert
                        size={14}
                        className="metric-icon"
                      />
                    </div>

                    <div
                      className={`metric-value ${
                        anomalyCount > 0
                          ? "bad-text"
                          : "good-text"
                      }`}
                    >
                      {anomalyCount}
                    </div>

                    <div className="metric-sub">
                      ML anomaly detections
                    </div>
                  </div>
                </div>
              </section>

              <div className="section-grid">
                <section className="card glass-panel">
                  <div className="card-header">
                    <div>
                      <div className="section-eyebrow">
                        RISK DISTRIBUTION
                      </div>

                      <h3>
                        Security Severity
                      </h3>
                    </div>

                    <ShieldAlert size={15} />
                  </div>

                  <div className="config-list">
                    <ConfigRow
                      label="Low risk"
                      value={`${riskCounts.low} sessions`}
                      valueClass="good"
                    />

                    <ConfigRow
                      label="Medium risk"
                      value={`${riskCounts.medium} sessions`}
                      valueClass="warning"
                    />

                    <ConfigRow
                      label="High risk"
                      value={`${riskCounts.high} sessions`}
                      valueClass={
                        riskCounts.high > 0
                          ? "bad"
                          : "good"
                      }
                    />

                    <ConfigRow
                      label="Critical risk"
                      value={`${riskCounts.critical} sessions`}
                      valueClass={
                        riskCounts.critical > 0
                          ? "bad"
                          : "good"
                      }
                    />

                    <ConfigRow
                      label="Certificate issues"
                      value={`${certificateIssueCount} sessions`}
                      valueClass={
                        certificateIssueCount > 0
                          ? "warning"
                          : "good"
                      }
                    />
                  </div>
                </section>

                <section className="card glass-panel">
                  <div className="card-header">
                    <div>
                      <div className="section-eyebrow">
                        PROTOCOL COVERAGE
                      </div>

                      <h3>Email Protocols</h3>
                    </div>

                    <Network size={15} />
                  </div>

                  <div className="config-list">
                    {Object.entries(
                      protocolCounts
                    ).map(([protocol, count]) => (
                      <ConfigRow
                        key={protocol}
                        label={protocol}
                        value={`${count} session${
                          count === 1
                            ? ""
                            : "s"
                        }`}
                      />
                    ))}
                  </div>
                </section>
              </div>

              <section
                className="card glass-panel"
                id="network-sessions"
              >
                <div className="card-header">
                  <div>
                    <div className="section-eyebrow">
                      NETWORK SESSIONS
                    </div>

                    <h3>
                      Analyzed Email Sessions
                    </h3>
                  </div>

                  <FileSearch size={15} />
                </div>

                <div className="session-selector">
                  {sessions.map(
                    (currentSession, index) => {
                      const severity =
                        currentSession?.posture
                          ?.security?.severity ||
                        "Unknown";

                      const sessionClass =
                        getSeverityClass(
                          severity
                        );

                      const sessionTls =
                        currentSession?.tls
                          ?.negotiated_tls_version ||
                        currentSession?.features
                          ?.tls_version ||
                        "No negotiated TLS";

                      return (
                        <button
                          key={`${
                            currentSession?.stream_id ??
                            "unknown"
                          }-${index}`}
                          className={`session-item ${
                            safeSelectedSessionIndex ===
                            index
                              ? "selected"
                              : ""
                          }`}
                          onClick={() =>
                            setSelectedSessionIndex(
                              index
                            )
                          }
                        >
                          <div className="session-item-left">
                            <span className="session-index">
                              {String(
                                index + 1
                              ).padStart(2, "0")}
                            </span>

                            <div>
                              <strong>
                                {getSessionTitle(
                                  currentSession,
                                  index
                                )}
                              </strong>

                              <span>
                                {sessionTls}
                              </span>
                            </div>
                          </div>

                          <div className="session-item-right">
                            <span
                              className={`badge ${sessionClass}`}
                            >
                              {severity}
                            </span>

                            <ArrowRight size={13} />
                          </div>
                        </button>
                      );
                    }
                  )}
                </div>
              </section>

              {session && (
                <>
                  <div className="analysis-meta glass-panel">
                    <div>
                      <span>
                        Selected session
                      </span>

                      <strong>
                        {safeSelectedSessionIndex +
                          1}{" "}
                        / {sessions.length}
                      </strong>
                    </div>

                    <div>
                      <span>Protocol</span>
                      <strong>
                        {session.protocol ||
                          "Unknown"}
                      </strong>
                    </div>

                    <div>
                      <span>TCP stream</span>
                      <strong>
                        #{session.stream_id ??
                          "Unknown"}
                      </strong>
                    </div>

                    <div>
                      <span>TLS observed</span>
                      <strong>
                        {tlsDetected
                          ? "Yes"
                          : "No"}
                      </strong>
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
                            <strong>
                              {score}
                            </strong>

                            <span>
                              Security score
                            </span>
                          </div>
                        </div>

                        <div className="score-details">
                          <div className="section-eyebrow">
                            RULE-BASED ASSESSMENT
                          </div>

                          <h2>
                            {securitySeverity} Risk
                          </h2>

                          <p>
                            Cryptographic
                            configuration analyzed
                            against SecureMailScope
                            security rules.
                          </p>

                          <span
                            className={`badge ${scoreClass}`}
                          >
                            {severityLabel}
                          </span>
                        </div>
                      </div>
                    </section>

                    <div className="metric-grid">
                      <div
                        className="metric-card glass-panel"
                        id="tls-analysis"
                      >
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
                          Negotiated protocol
                          version
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
                          {getCipherDisplayName(
                            cipher
                          )}
                        </div>

                        <div
                          className="metric-sub"
                          title={cipher}
                        >
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
                          {forwardSecrecyLabel}
                        </div>
                      </div>

                      <div
                        className="metric-card glass-panel"
                        id="certificate-analysis"
                      >
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
                              : certificatePresent
                                ? "bad-text"
                                : ""
                          }`}
                        >
                          {certificateValid
                            ? "Valid"
                            : certificatePresent
                              ? "Issue detected"
                              : "Unavailable"}
                        </div>

                        <div
                          className="metric-sub"
                          title={getCertificateDisplay()}
                        >
                          {getCertificateDisplay()}
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

                          <h3>
                            Security Configuration
                          </h3>
                        </div>

                        <LockKeyhole size={15} />
                      </div>

                      <div className="config-list">
                        <ConfigRow
                          label="Protocol"
                          value={
                            features?.protocol ||
                            session.protocol ||
                            "Unknown"
                          }
                        />

                        <ConfigRow
                          label="TLS observed"
                          value={
                            tlsDetected
                              ? "Detected"
                              : "Not detected"
                          }
                          valueClass={
                            tlsDetected
                              ? "good"
                              : "bad"
                          }
                        />

                        <ConfigRow
                          label="Negotiated TLS"
                          value={tlsVersion}
                          valueClass={
                            !tlsDetected
                              ? "warning"
                              : tlsVersion ===
                                  "TLS 1.3"
                                ? "good"
                                : tlsVersion ===
                                    "TLS 1.2"
                                  ? "warning"
                                  : "bad"
                          }
                        />

                        <ConfigRow
                          label="Cipher suite"
                          value={cipher}
                          valueClass={
                            !tlsDetected
                              ? "warning"
                              : cipher.includes(
                                    "CBC"
                                  )
                                ? "bad"
                                : "good"
                          }
                        />

                        <ConfigRow
                          label="Key exchange"
                          value={keyExchange}
                          valueClass={
                            !tlsDetected
                              ? "warning"
                              : keyExchange ===
                                  "RSA"
                                ? "bad"
                                : "good"
                          }
                        />

                        <ConfigRow
                          label="Public key"
                          value={
                            certificatePresent
                              ? `${certificate?.public_key_algorithm || "Unknown"} ${keySize}`
                              : "Not detected"
                          }
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
                              : certificate?.signature_algorithm
                                ? "good"
                                : ""
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

                          <h3>
                            TLS & STARTTLS
                            Posture
                          </h3>
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
                              : tlsDetected
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
                              : "warning"
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
                              : tlsDetected
                                ? "good"
                                : "bad"
                          }
                        />

                        <ConfigRow
                          label="Forward secrecy"
                          value={forwardSecrecyLabel}
                          valueClass={
                            !tlsDetected
                              ? "warning"
                              : forwardSecrecy
                                ? "good"
                                : "bad"
                          }
                        />

                        <ConfigRow
                          label="Certificate validity"
                          value={
                            certificateValid
                              ? "Currently valid"
                              : certificatePresent
                                ? "Invalid / unavailable"
                                : "Not available"
                          }
                          valueClass={
                            certificateValid
                              ? "good"
                              : certificatePresent
                                ? "bad"
                                : "warning"
                          }
                        />

                        <ConfigRow
                          label="Anomaly detection"
                          value={
                            posture?.anomaly
                              ?.is_anomaly
                              ? "Anomaly detected"
                              : "No anomaly"
                          }
                          valueClass={
                            posture?.anomaly
                              ?.is_anomaly
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

                        <h3>
                          AI Security Assessment
                        </h3>
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
                            <strong>
                              {riskLabel} Risk
                            </strong>

                            <span>
                              ML classification
                              confidence:{" "}
                              {riskConfidence}
                            </span>
                          </div>
                        </div>

                        <div className="confidence">
                          <div className="confidence-head">
                            <span>
                              Confidence
                            </span>

                            <strong>
                              {riskConfidence}
                            </strong>
                          </div>

                          <div className="confidence-bar">
                            <span
                              style={{
                                width: `${confidence * 100}%`,
                              }}
                            />
                          </div>
                        </div>

                        <div
                          className={`anomaly-status ${
                            posture?.anomaly
                              ?.is_anomaly
                              ? "anomaly"
                              : ""
                          }`}
                        >
                          {posture?.anomaly
                            ?.is_anomaly ? (
                            <AlertTriangle
                              size={13}
                            />
                          ) : (
                            <CheckCircle2
                              size={13}
                            />
                          )}

                          <span>
                            {posture?.anomaly
                              ?.is_anomaly
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

                          <h3>
                            Security Findings
                          </h3>
                        </div>

                        <AlertTriangle size={15} />
                      </div>

                      <div className="findings-list">
                        {findings.length ===
                        0 ? (
                          <div className="no-findings">
                            <CheckCircle2 size={15} />
                            No security findings
                            detected.
                          </div>
                        ) : (
                          findings.map(
                            (finding, index) => (
                              <div
                                className="finding"
                                key={`finding-${index}`}
                              >
                                <div className="finding-icon">
                                  <AlertTriangle
                                    size={14}
                                  />
                                </div>

                                <div className="finding-content">
                                  <strong>
                                    Security weakness
                                    detected
                                  </strong>

                                  <p>{finding}</p>
                                </div>
                              </div>
                            )
                          )
                        )}
                      </div>
                    </section>

                    <section className="card glass-panel">
                      <div className="card-header">
                        <div>
                          <div className="section-eyebrow">
                            REMEDIATION
                          </div>

                          <h3>
                            Recommendations
                          </h3>
                        </div>

                        <ArrowRight size={15} />
                      </div>

                      <div className="recommendation-list">
                        {recommendations.length ===
                        0 ? (
                          <div className="no-findings">
                            <CheckCircle2 size={15} />
                            No recommendations
                            required.
                          </div>
                        ) : (
                          recommendations.map(
                            (
                              recommendation,
                              index
                            ) => (
                              <div
                                className="recommendation"
                                key={`recommendation-${index}`}
                              >
                                <div className="recommendation-number">
                                  {String(
                                    index + 1
                                  ).padStart(
                                    2,
                                    "0"
                                  )}
                                </div>

                                <p>
                                  {recommendation}
                                </p>
                              </div>
                            )
                          )
                        )}
                      </div>
                    </section>
                  </div>

                  <div className="analysis-footer">
                    <span>
                      Passive network forensic
                      analysis • No traffic
                      modification
                    </span>

                    <strong>
                      {sessions.length} email
                      session
                      {sessions.length === 1
                        ? ""
                        : "s"}{" "}
                      analyzed
                    </strong>
                  </div>
                </>
              )}
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

      <strong
        className={`config-value ${valueClass}`}
        title={String(value ?? "")}
      >
        {value}
      </strong>
    </div>
  );
}

export default App;