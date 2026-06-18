import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

const EXPLOIT_PLAYBOOKS = {
  upgradeable_logic: {
    title: "Upgradeable Logic Abuse",
    where: "Proxy admin paths, implementation setters, delegatecall upgrade routines.",
    how: "Attacker abuses weak upgrade authorization or compromised admin keys to swap malicious logic.",
    sequence: [
      "Deploy malicious implementation contract.",
      "Trigger upgrade function to point proxy to malicious implementation.",
      "Call privileged initializer or role-setting function.",
      "Execute drain, mint, or permission hijack routines.",
    ],
    impact: "Full contract takeover and potential direct fund loss.",
    monitor: "Unexpected implementation change events and out-of-window upgrade transactions.",
  },
  admin_pause_control: {
    title: "Admin Pause Control Abuse",
    where: "Owner/admin modifiers and emergency pause-unpause functions.",
    how: "Compromised or malicious admin pauses user actions, then changes protocol state in a privileged window.",
    sequence: [
      "Call pause function to halt normal user operations.",
      "Change sensitive parameters while users cannot react.",
      "Execute privileged transfers or role updates.",
      "Unpause with attacker-favorable configuration in place.",
    ],
    impact: "Operational denial of service, governance abuse, and possible treasury or user loss.",
    monitor: "Pause events closely followed by admin-only parameter changes or fund movements.",
  },
  external_call_surface: {
    title: "External Call / Callback Abuse",
    where: "Functions issuing low-level calls, staticcall/delegatecall, or third-party protocol callbacks.",
    how: "Attacker contract re-enters or manipulates callback assumptions before internal state finalization.",
    sequence: [
      "Deploy attacker callback contract.",
      "Invoke target function that performs external call before state updates.",
      "Re-enter vulnerable function during callback.",
      "Repeat until limits or balances are bypassed/drained.",
    ],
    impact: "Accounting corruption and potential unauthorized withdrawals.",
    monitor: "Repeated nested calls to same function and unusual balance deltas in one transaction.",
  },
  oracle_dependency: {
    title: "Oracle Manipulation / Stale Price Exploit",
    where: "Borrow, collateral, liquidation, mint, or redemption paths reading price feeds.",
    how: "Attacker distorts or races oracle-dependent pricing to execute underpriced borrows or favorable liquidations.",
    sequence: [
      "Use large temporary capital (often flash liquidity).",
      "Distort reference market or exploit stale update window.",
      "Trigger borrow/liquidation/redemption using manipulated price.",
      "Restore market and keep extracted value spread.",
    ],
    impact: "Bad debt creation, liquidation cascades, and insolvency pressure.",
    monitor: "Large short-lived price deviations near sensitive protocol actions.",
  },
  slither_nonzero_exit: {
    title: "Static Analysis Failure Triage",
    where: "Analyzer-incomplete or parser-sensitive code paths flagged by Slither run status.",
    how: "Not directly exploitable by itself, but can hide unresolved real issues unless manually triaged.",
    sequence: [
      "Re-run static analysis with pinned compiler/dependency versions.",
      "Isolate failing detectors or source regions.",
      "Stress privileged and boundary-case function inputs.",
      "Escalate any unexpected state transition to exploit candidate.",
    ],
    impact: "False sense of safety if unresolved findings are ignored.",
    monitor: "Repeated non-zero analyzer exits on same contracts or same function families.",
  },
};

function normalizeFindingTag(vulnerability) {
  const lowered = String(vulnerability || "").toLowerCase();
  if (lowered.startsWith("defi_risk:")) return lowered.split(":")[1] || lowered;
  return lowered;
}

function buildExploitPlaybooks(vulnerabilities) {
  const uniqueKeys = [...new Set((vulnerabilities || []).map(normalizeFindingTag))];
  return uniqueKeys.map((key) => {
    const template = EXPLOIT_PLAYBOOKS[key];
    if (template) {
      return { key, ...template };
    }
    return {
      key,
      title: `Manual Review Playbook: ${key || "unknown_finding"}`,
      where: "Inspect the exact function path flagged by the scanner in source and runtime traces.",
      how: "Attacker may combine this condition with privilege misuse, ordering bugs, or integration assumptions.",
      sequence: [
        "Identify caller permissions and trust boundaries.",
        "Attempt boundary-case inputs and unexpected call ordering.",
        "Trace state changes before and after external interactions.",
        "Confirm whether value, roles, or invariants can be violated.",
      ],
      impact: "Potentially meaningful risk; exploitability must be confirmed by targeted testing.",
      monitor: "Alert on function usage spikes and anomalous state transitions around this path.",
    };
  });
}

function formatDate(input) {
  try {
    return new Date(input).toLocaleString();
  } catch {
    return input;
  }
}

function shortHash(value) {
  if (!value || value.length < 12) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function formatEth(value) {
  if (value === null || value === undefined) return "-";
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  if (n === 0) return "0";
  if (n >= 1000) return n.toLocaleString(undefined, { maximumFractionDigits: 2 });
  if (n >= 1) return n.toFixed(4);
  return n.toFixed(6);
}

function maybe(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function getRouteState() {
  return {
    pathname: window.location.pathname,
    search: window.location.search,
  };
}

function navigateTo(path) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function buildContractPath(row) {
  return `/contract/${row.address}?scanned_at=${encodeURIComponent(row.scanned_at)}`;
}

function buildReportPath(row, generatedAt) {
  const base = buildContractPath(row);
  return `${base}&report=1&generated_at=${encodeURIComponent(generatedAt)}`;
}

function buildClientBrief(row) {
  const header = [
    "Contract Risk Brief",
    "===================",
    `Address: ${row.address}`,
    `Status: ${row.status}`,
    `Scanned At: ${row.scanned_at}`,
    `Summary: ${row.summary}`,
    "",
    "Findings",
    "--------",
  ];

  if (!row.vulnerability_details?.length) {
    return [...header, "No detailed findings available."].join("\n");
  }

  const sections = row.vulnerability_details.flatMap((detail, idx) => [
    `${idx + 1}. ${detail.title} (${detail.severity})`,
    `What it means: ${detail.what_it_means}`,
    `How it can be used: ${detail.how_it_can_be_used}`,
    `Client impact: ${detail.client_impact}`,
    "",
  ]);

  return [...header, ...sections].join("\n");
}

function DashboardPage({ rows, loading, error, onRefresh, minLiquidityEth, maxLiquidityEth, onMinLiquidityChange, onMaxLiquidityChange, search, onSearchChange }) {
  const metrics = useMemo(() => {
    const total = rows.length;
    const vulnerable = rows.filter((r) => r.vulnerabilities?.length > 0).length;
    const safe = total - vulnerable;
    const findings = rows.reduce((acc, row) => acc + (row.vulnerabilities?.length || 0), 0);
    return { total, vulnerable, safe, findings };
  }, [rows]);

  return (
    <>
      <header className="hero">
        <p className="kicker">ON-CHAIN SENTINEL</p>
        <h1>Contract Risk Radar</h1>
        <p className="subtitle">
          Continuous deployment monitoring, automated triage, and vulnerability signal tracking
          across newly created smart contracts.
        </p>
      </header>

      <section className="metrics">
        <article className="metric-card">
          <span>Total Scans</span>
          <strong>{metrics.total}</strong>
        </article>
        <article className="metric-card">
          <span>Contracts With Findings</span>
          <strong>{metrics.vulnerable}</strong>
        </article>
        <article className="metric-card">
          <span>Contracts Without Findings</span>
          <strong>{metrics.safe}</strong>
        </article>
        <article className="metric-card">
          <span>Total Findings</span>
          <strong>{metrics.findings}</strong>
        </article>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Recent Scan Results</h2>
          <div className="panel-controls">
            <input
              type="text"
              className="search-input"
              placeholder="Search by contract address..."
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
            />
            <label className="liquidity-filter">
              Min ETH
              <input
                type="number"
                min="0"
                step="0.01"
                value={minLiquidityEth}
                onChange={(e) => onMinLiquidityChange(e.target.value)}
                placeholder="0"
              />
            </label>
            <label className="liquidity-filter">
              Max ETH
              <input
                type="number"
                min="0"
                step="0.01"
                value={maxLiquidityEth}
                onChange={(e) => onMaxLiquidityChange(e.target.value)}
                placeholder="No max"
              />
            </label>
            <button onClick={onRefresh} disabled={loading}>
              {loading ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>

        {error ? <p className="error">{error}</p> : null}

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>Creator</th>
                <th>Proxy</th>
                <th>Activity</th>
                <th>Block</th>
                <th>Status</th>
                <th>Vulnerabilities</th>
                <th>Liquidity (ETH)</th>
                <th>Scanned At</th>
              </tr>
            </thead>
            <tbody>
              {!rows.length && !loading ? (
                <tr>
                  <td colSpan="9" className="empty">
                    No scan results yet. Start the backend scanner to populate data.
                  </td>
                </tr>
              ) : (
                rows.map((row, idx) => (
                  <tr
                    key={row.address + row.scanned_at}
                    style={{ animationDelay: `${idx * 50}ms` }}
                    className="scan-row"
                    onClick={() => navigateTo(buildContractPath(row))}
                  >
                    <td title={row.address}>{shortHash(row.address)}</td>
                    <td title={row.creator_address || ""}>{row.creator_address ? shortHash(row.creator_address) : "-"}</td>
                    <td>{row.is_proxy === null || row.is_proxy === undefined ? "-" : row.is_proxy ? "Yes" : "No"}</td>
                    <td>{row.activity_score === null || row.activity_score === undefined ? "-" : row.activity_score}</td>
                    <td>{row.block_number}</td>
                    <td>
                      <span className={row.vulnerabilities?.length ? "pill risk" : "pill ok"}>
                        {row.status}
                      </span>
                    </td>
                    <td>{row.vulnerabilities?.length ? row.vulnerabilities.join(", ") : "none"}</td>
                    <td>{formatEth(row.liquidity_eth)}</td>
                    <td>{formatDate(row.scanned_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function ContractDetailPage({ row, reportMode, reportGeneratedAt }) {
  const [shareCopied, setShareCopied] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [profile, setProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);
  const [profileError, setProfileError] = useState("");
  const [rescanLoading, setRescanLoading] = useState(false);
  const [rescanStatus, setRescanStatus] = useState("");

  useEffect(() => {
    if (!reportMode || !row) return;
    const id = window.setTimeout(() => {
      window.print();
    }, 120);
    return () => window.clearTimeout(id);
  }, [reportMode, row]);

  useEffect(() => {
    if (!row) return;

    let cancelled = false;
    const loadProfile = async () => {
      setProfileLoading(true);
      setProfileError("");
      try {
        const response = await fetch(`${API_BASE}/api/contracts/${encodeURIComponent(row.address)}/profile`);
        if (!response.ok) throw new Error("Failed to load Etherscan profile");
        const data = await response.json();
        if (!cancelled) setProfile(data);
      } catch (err) {
        if (!cancelled) setProfileError(err.message || "Failed to load Etherscan profile");
      } finally {
        if (!cancelled) setProfileLoading(false);
      }
    };

    loadProfile();
    return () => {
      cancelled = true;
    };
  }, [row]);

  if (!row) {
    return (
      <section className="panel contract-panel">
        <button className="ghost-btn" onClick={() => navigateTo("/")}>Back To Dashboard</button>
        <p className="empty-detail">Contract details not found. Refresh dashboard data and try again.</p>
      </section>
    );
  }

  const downloadBrief = () => {
    const content = buildClientBrief(row);
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = `contract-brief-${row.address}.txt`;
    a.click();
    URL.revokeObjectURL(href);
  };

  const copyShareLink = async () => {
    const shareUrl = window.location.href;
    try {
      await navigator.clipboard.writeText(shareUrl);
      setShareCopied(true);
      window.setTimeout(() => setShareCopied(false), 1500);
    } catch {
      // Clipboard API can fail in restricted contexts.
      setShareCopied(false);
    }
  };

  const printable = () => {
    window.print();
  };

  const exportStandardPdf = () => {
    const generatedAt = new Date().toISOString();
    navigateTo(buildReportPath(row, generatedAt));
  };

  const refreshProfile = async () => {
    setProfileLoading(true);
    setProfileError("");
    try {
      const response = await fetch(
        `${API_BASE}/api/contracts/${encodeURIComponent(row.address)}/profile?refresh=1`
      );
      if (!response.ok) throw new Error("Failed to refresh Etherscan profile");
      const data = await response.json();
      setProfile(data);
    } catch (err) {
      setProfileError(err.message || "Failed to refresh Etherscan profile");
    } finally {
      setProfileLoading(false);
    }
  };

  const manualRescan = async () => {
    setRescanLoading(true);
    setRescanStatus("");
    try {
      const response = await fetch(
        `${API_BASE}/api/rescan/${encodeURIComponent(row.address)}`,
        { method: "POST" }
      );
      if (!response.ok) throw new Error("Failed to queue rescan");
      const data = await response.json();
      setRescanStatus(`Rescan queued: ${data.status}`);
      window.setTimeout(() => setRescanStatus(""), 3000);
    } catch (err) {
      setRescanStatus(`Rescan error: ${err.message || "Unknown error"}`);
    } finally {
      setRescanLoading(false);
    }
  };

  const sortedDetails = [...(row.vulnerability_details || [])].sort((a, b) => {
    const rank = { high: 0, medium: 1, low: 2, informational: 3 };
    const left = rank[a.severity] ?? 9;
    const right = rank[b.severity] ?? 9;
    if (left !== right) return left - right;
    return (a.title || "").localeCompare(b.title || "");
  });

  const filteredDetails = reportMode
    ? sortedDetails
    : severityFilter === "all"
      ? sortedDetails
      : sortedDetails.filter((detail) => detail.severity === severityFilter);

  const exploitPlaybooks = buildExploitPlaybooks(row.vulnerabilities || []);

  const severityCounts = (row.vulnerability_details || []).reduce(
    (acc, detail) => {
      const level = detail.severity || "informational";
      acc[level] = (acc[level] || 0) + 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0, informational: 0 }
  );

  return (
    <section className={`panel contract-panel ${reportMode ? "report-mode" : ""}`}>
      {reportMode ? (
        <header className="report-header">
          <p className="report-brand">Contract Monitor</p>
          <h1 className="report-title">Smart Contract Security Report</h1>
          <p className="report-meta-line">
            Generated At: {formatDate(reportGeneratedAt || row.scanned_at)}
          </p>
          <p className="report-meta-line">Assessment Type: Automated Vulnerability Triage</p>
        </header>
      ) : null}

      <div className="panel-head contract-head">
        {!reportMode ? (
          <>
            <button className="ghost-btn no-print" onClick={() => navigateTo("/")}>Back To Dashboard</button>
            <div className="contract-actions no-print">
              <button className="ghost-btn" onClick={copyShareLink}>
                {shareCopied ? "Link Copied" : "Share Link"}
              </button>
              <button className="ghost-btn" onClick={printable}>Print / Save PDF</button>
              <button className="ghost-btn" onClick={exportStandardPdf}>Export Standard PDF</button>
              <button onClick={downloadBrief}>Download Client Brief</button>
            </div>
          </>
        ) : null}
      </div>

      <h2>Contract Findings</h2>
      <p className="contract-meta"><strong>Address:</strong> {row.address}</p>
      <p className="contract-meta"><strong>Status:</strong> {row.status}</p>
      <p className="contract-meta"><strong>Scanned:</strong> {formatDate(row.scanned_at)}</p>
      <p className="detail-summary">{row.summary}</p>

      <section className="profile-section">
        <div className="profile-header">
          <h3>Etherscan Contract Intelligence</h3>
          {!reportMode ? (
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button className="ghost-btn no-print" onClick={refreshProfile} disabled={profileLoading}>
                {profileLoading ? "Refreshing profile..." : "Refresh Etherscan Profile"}
              </button>
              <button className="ghost-btn no-print" onClick={manualRescan} disabled={rescanLoading}>
                {rescanLoading ? "Queuing rescan..." : "Manual Rescan"}
              </button>
            </div>
          ) : null}
          {rescanStatus ? <p className="info-status no-print">{rescanStatus}</p> : null}
        </div>

        {profileError ? <p className="error">{profileError}</p> : null}
        {!profile ? (
          <p className="empty-detail">{profileLoading ? "Loading Etherscan profile..." : "No profile data yet."}</p>
        ) : (
          <>
            <div className="profile-meta">
              <p><strong>Cached At:</strong> {maybe(profile._meta?.cached_at)}</p>
              <p><strong>Cache Age (s):</strong> {maybe(profile._meta?.cache_age_seconds ? profile._meta.cache_age_seconds.toFixed(1) : 0)}</p>
              <p><strong>TTL (s):</strong> {maybe(profile._meta?.cache_ttl_seconds)}</p>
              <p><strong>Backoff (s):</strong> {maybe(profile._meta?.refresh_backoff_seconds)}</p>
              <p><strong>Rate Limited:</strong> {maybe(profile._meta?.rate_limited)}</p>
              <p><strong>Last Refresh Error:</strong> {maybe(profile._meta?.last_refresh_error)}</p>
            </div>

            <article className="profile-card profile-wide">
              <h4>Snapshot Diff (Last Refresh)</h4>
              <p><strong>Changed Fields:</strong> {maybe(profile._diff?.changed_count)}</p>
              <p><strong>From:</strong> {maybe(profile._diff?.from_snapshot_at)}</p>
              <p><strong>To:</strong> {maybe(profile._diff?.to_snapshot_at)}</p>
              {(profile._diff?.changes || []).length ? (
                <div className="diff-list">
                  {profile._diff.changes.map((change, idx) => (
                    <div key={`${change.field}-${idx}`} className="diff-item">
                      <p><strong>{change.field}</strong></p>
                      <p>Old: {maybe(change.old)}</p>
                      <p>New: {maybe(change.new)}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No field changes between latest snapshots.</p>
              )}
            </article>

            <article className="profile-card profile-wide">
              <h4>Snapshot Timeline</h4>
              {(profile._snapshots || []).length ? (
                <ul>
                  {profile._snapshots.map((snap) => (
                    <li key={snap.id}>#{snap.id} at {snap.created_at}</li>
                  ))}
                </ul>
              ) : (
                <p>No snapshots saved yet.</p>
              )}
            </article>

            <div className="profile-grid">
            <article className="profile-card">
              <h4>1) Source Metadata</h4>
              <p><strong>Verified:</strong> {maybe(profile.contract_source_metadata?.verified)}</p>
              <p><strong>Contract Name:</strong> {maybe(profile.contract_source_metadata?.contract_name)}</p>
              <p><strong>Compiler:</strong> {maybe(profile.contract_source_metadata?.compiler_version)}</p>
              <p><strong>Optimization:</strong> {maybe(profile.contract_source_metadata?.optimization_used)}</p>
              <p><strong>Runs:</strong> {maybe(profile.contract_source_metadata?.optimization_runs)}</p>
              <p><strong>EVM Version:</strong> {maybe(profile.contract_source_metadata?.evm_version)}</p>
              <p><strong>License:</strong> {maybe(profile.contract_source_metadata?.license_type)}</p>
            </article>

            <article className="profile-card">
              <h4>2) Creator/Deployment</h4>
              <p><strong>Creator:</strong> {maybe(profile.creator_deployment_context?.creator_address)}</p>
              <p><strong>Deploy TX:</strong> {maybe(profile.creator_deployment_context?.deploy_tx_hash)}</p>
              <p><strong>Deploy Block:</strong> {maybe(profile.creator_deployment_context?.deploy_block)}</p>
              <p><strong>Deploy Time:</strong> {maybe(profile.creator_deployment_context?.deploy_time)}</p>
              <p><strong>First Funding TX:</strong> {maybe(profile.creator_deployment_context?.first_funding_tx_hash)}</p>
            </article>

            <article className="profile-card">
              <h4>3) ABI Inventory</h4>
              <p><strong>ABI Available:</strong> {maybe(profile.abi_inventory?.abi_available)}</p>
              <p><strong>Public/External Functions:</strong> {maybe(profile.abi_inventory?.public_or_external_functions)}</p>
              <p><strong>Payable Functions:</strong> {maybe(profile.abi_inventory?.payable_functions)}</p>
              <p><strong>Events:</strong> {maybe(profile.abi_inventory?.events)}</p>
              <p><strong>Admin-like Functions:</strong> {maybe(profile.abi_inventory?.admin_like_functions)}</p>
            </article>

            <article className="profile-card">
              <h4>4) Token Profile</h4>
              <p><strong>Name:</strong> {maybe(profile.token_profile?.token_name)}</p>
              <p><strong>Symbol:</strong> {maybe(profile.token_profile?.token_symbol)}</p>
              <p><strong>Decimals:</strong> {maybe(profile.token_profile?.token_decimals)}</p>
              <p><strong>Total Supply (raw):</strong> {maybe(profile.token_profile?.total_supply_raw)}</p>
              <p><strong>Holder Count:</strong> {maybe(profile.token_profile?.holder_count)}</p>
            </article>

            <article className="profile-card">
              <h4>5) Activity Metrics</h4>
              <p><strong>Normal TX Count:</strong> {maybe(profile.transfer_activity_metrics?.normal_tx_count)}</p>
              <p><strong>Internal TX Count:</strong> {maybe(profile.transfer_activity_metrics?.internal_tx_count)}</p>
              <p><strong>Token Transfer Count:</strong> {maybe(profile.transfer_activity_metrics?.token_transfer_count)}</p>
              <p><strong>First Seen:</strong> {maybe(profile.transfer_activity_metrics?.first_seen_at)}</p>
              <p><strong>Last Seen:</strong> {maybe(profile.transfer_activity_metrics?.last_seen_at)}</p>
            </article>

            <article className="profile-card">
              <h4>6) Balance/Value Flow</h4>
              <p><strong>Current Balance (wei):</strong> {maybe(profile.balance_value_flow?.current_eth_balance_wei)}</p>
              <p><strong>Total Incoming (wei):</strong> {maybe(profile.balance_value_flow?.total_incoming_wei)}</p>
              <p><strong>Total Outgoing (wei):</strong> {maybe(profile.balance_value_flow?.total_outgoing_wei)}</p>
              <p><strong>Net Flow (wei):</strong> {maybe(profile.balance_value_flow?.net_flow_wei)}</p>
              <p><strong>Flow Sample Size:</strong> {maybe(profile.balance_value_flow?.flow_sample_size)}</p>
            </article>

            <article className="profile-card">
              <h4>7) Labels/Tags</h4>
              <p><strong>Contract Name Label:</strong> {maybe(profile.labels_and_tags?.contract_name_label)}</p>
              <p><strong>License Label:</strong> {maybe(profile.labels_and_tags?.license_label)}</p>
            </article>

            <article className="profile-card">
              <h4>8) Proxy/Upgrade Intelligence</h4>
              <p><strong>Is Proxy:</strong> {maybe(profile.proxy_upgrade_intelligence?.is_proxy)}</p>
              <p><strong>Implementation:</strong> {maybe(profile.proxy_upgrade_intelligence?.implementation_address)}</p>
              <p><strong>Signal:</strong> {maybe(profile.proxy_upgrade_intelligence?.upgradeability_signal)}</p>
            </article>

            <article className="profile-card">
              <h4>9) Clone Relationships</h4>
              <p><strong>Potential Clone:</strong> {maybe(profile.clone_relationships?.is_potential_clone)}</p>
              <p><strong>Similar Match Address:</strong> {maybe(profile.clone_relationships?.similar_match_address)}</p>
            </article>

            <article className="profile-card">
              <h4>10) Verification/Audit Breadcrumbs</h4>
              <p><strong>Verified:</strong> {maybe(profile.verification_audit_breadcrumbs?.verified)}</p>
              <p><strong>Source:</strong> {maybe(profile.verification_audit_breadcrumbs?.verification_source)}</p>
              <p><strong>Compiler:</strong> {maybe(profile.verification_audit_breadcrumbs?.compiler_version)}</p>
              <p><strong>Contract Name:</strong> {maybe(profile.verification_audit_breadcrumbs?.contract_name)}</p>
              <p><strong>License:</strong> {maybe(profile.verification_audit_breadcrumbs?.license_type)}</p>
            </article>

            <article className="profile-card profile-wide">
              <h4>Coverage Notes</h4>
              {(profile.coverage_notes || []).length ? (
                <ul>
                  {profile.coverage_notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              ) : (
                <p>None</p>
              )}
            </article>
            </div>
          </>
        )}
      </section>

      {!reportMode ? (
        <div className="severity-filter no-print">
          <span>Filter by severity:</span>
          <button
            className={`filter-chip ${severityFilter === "all" ? "active" : ""}`}
            onClick={() => setSeverityFilter("all")}
          >
            All ({(row.vulnerability_details || []).length})
          </button>
          <button
            className={`filter-chip ${severityFilter === "high" ? "active" : ""}`}
            onClick={() => setSeverityFilter("high")}
          >
            High ({severityCounts.high || 0})
          </button>
          <button
            className={`filter-chip ${severityFilter === "medium" ? "active" : ""}`}
            onClick={() => setSeverityFilter("medium")}
          >
            Medium ({severityCounts.medium || 0})
          </button>
          <button
            className={`filter-chip ${severityFilter === "low" ? "active" : ""}`}
            onClick={() => setSeverityFilter("low")}
          >
            Low ({severityCounts.low || 0})
          </button>
          <button
            className={`filter-chip ${severityFilter === "informational" ? "active" : ""}`}
            onClick={() => setSeverityFilter("informational")}
          >
            Informational ({severityCounts.informational || 0})
          </button>
        </div>
      ) : null}

      {filteredDetails.length ? (
        filteredDetails.map((detail, index) => (
          <article key={`${detail.id}-${index}`} className="finding-card">
            <div className="finding-head">
              <h3>{detail.title}</h3>
              <span className={`severity severity-${detail.severity}`}>{detail.severity}</span>
            </div>
            <p>
              <strong>What it means:</strong> {detail.what_it_means}
            </p>
            <p>
              <strong>How it can be used:</strong> {detail.how_it_can_be_used}
            </p>
            <p>
              <strong>Client impact:</strong> {detail.client_impact}
            </p>
          </article>
        ))
      ) : (
        <p className="empty-detail">No findings match the selected severity filter.</p>
      )}

      {exploitPlaybooks.length ? (
        <section className="playbooks-section">
          <h2>Exploit Playbooks</h2>
          <p className="playbooks-intro">
            Automatically generated from scan findings to guide manual validation and incident response.
          </p>
          {exploitPlaybooks.map((playbook) => (
            <article key={playbook.key} className="playbook-card">
              <h3>{playbook.title}</h3>
              <p>
                <strong>Where the vulnerability is:</strong> {playbook.where}
              </p>
              <p>
                <strong>How it can be exploited:</strong> {playbook.how}
              </p>
              <p><strong>Concrete attacker transaction sequence:</strong></p>
              <ol className="playbook-sequence">
                {playbook.sequence.map((step, idx) => (
                  <li key={`${playbook.key}-${idx}`}>{step}</li>
                ))}
              </ol>
              <p>
                <strong>Likely impact:</strong> {playbook.impact}
              </p>
              <p>
                <strong>What to monitor:</strong> {playbook.monitor}
              </p>
            </article>
          ))}
        </section>
      ) : null}

      {reportMode ? (
        <footer className="report-footer">
          <p>This report is generated from automated analyzer output and should be validated by manual review before production decisions.</p>
          <p>Contract Monitor | {row.address}</p>
        </footer>
      ) : null}
    </section>
  );
}

export default function App() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [route, setRoute] = useState(getRouteState);
  const [minLiquidityEth, setMinLiquidityEth] = useState("");
  const [maxLiquidityEth, setMaxLiquidityEth] = useState("");
  const [search, setSearch] = useState("");

  const loadData = async () => {
    setError("");
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: "200" });
      if (minLiquidityEth !== "") params.set("min_liquidity_eth", minLiquidityEth);
      if (maxLiquidityEth !== "") params.set("max_liquidity_eth", maxLiquidityEth);
      if (search !== "") params.set("search", search);

      const response = await fetch(`${API_BASE}/api/contracts?${params.toString()}`);
      if (!response.ok) throw new Error("Failed to load dashboard data");
      const data = await response.json();
      setRows(data);
    } catch (err) {
      setError(err.message || "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 15000);
    return () => clearInterval(id);
  }, [minLiquidityEth, maxLiquidityEth, search]);

  useEffect(() => {
    const onPopState = () => setRoute(getRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const isContractRoute = route.pathname.startsWith("/contract/");
  const contractAddress = isContractRoute ? decodeURIComponent(route.pathname.split("/contract/")[1] || "") : "";
  const params = new URLSearchParams(route.search);
  const scannedAt = params.get("scanned_at") || "";
  const reportMode = params.get("report") === "1";
  const reportGeneratedAt = params.get("generated_at") || "";

  const selectedRow = useMemo(() => {
    if (!isContractRoute) return null;
    return (
      rows.find((row) => row.address === contractAddress && row.scanned_at === scannedAt) ||
      rows.find((row) => row.address === contractAddress) ||
      null
    );
  }, [rows, isContractRoute, contractAddress, scannedAt]);

  return (
    <div className="page">
      <div className="bg-grid" />
      {isContractRoute ? (
        <ContractDetailPage
          row={selectedRow}
          reportMode={reportMode}
          reportGeneratedAt={reportGeneratedAt}
        />
      ) : (
        <DashboardPage
          rows={rows}
          loading={loading}
          error={error}
          onRefresh={loadData}
          minLiquidityEth={minLiquidityEth}
          maxLiquidityEth={maxLiquidityEth}
          onMinLiquidityChange={setMinLiquidityEth}
          onMaxLiquidityChange={setMaxLiquidityEth}
          search={search}
          onSearchChange={setSearch}
        />
      )}
    </div>
  );
}
