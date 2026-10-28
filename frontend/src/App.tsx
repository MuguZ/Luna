
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  Activity,
  ArrowUpRight,
  Bell,
  CheckCircle2,
  ChevronDown,
  Command,
  FileSearch,
  Fingerprint,
  Gauge,
  Layers3,
  LockKeyhole,
  Network,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Upload,
  Wifi,
  WifiOff,
  Download,
  Trash2,
  X,
} from "lucide-react";
import { apiRequest, deleteInvestigation, fetchDetectionRules, fetchInvestigation, fetchInvestigations } from "./api";
import type { AnalysisResponse, DetectionRule, InvestigationPage, InvestigationSummary } from "./api";

type ApiStatus = "checking" | "online" | "offline";

type HealthResponse = {
  status: string;
  service: string;
};

type SecurityEventInput = Record<string, unknown> & {
  event_id: string;
  timestamp: string;
  event_type: string;
  source: string;
};

type AnalysisSource = "demo" | "upload";
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const MAX_EVENTS = 10_000;
const REQUIRED_EVENT_FIELDS = ["event_id", "timestamp", "event_type", "source"] as const;
const OPTIONAL_STRING_FIELDS = ["username", "source_ip", "outcome", "resource", "message"] as const;

function validateUploadedEvents(value: unknown): SecurityEventInput[] {
  const events = Array.isArray(value)
    ? value
    : value && typeof value === "object" && Array.isArray((value as { events?: unknown }).events)
      ? (value as { events: unknown[] }).events
      : null;
  if (!events) throw new Error('JSON must be an array of events or an object with an "events" array.');
  if (!events.length) throw new Error("The event list is empty. Add at least one event.");
  if (events.length > MAX_EVENTS) throw new Error(`A maximum of ${MAX_EVENTS.toLocaleString()} events is allowed.`);
  const seenIds = new Set<string>();
  events.forEach((event, index) => {
    const row = index + 1;
    if (!event || typeof event !== "object" || Array.isArray(event)) throw new Error(`Event ${row} must be a JSON object.`);
    const record = event as Record<string, unknown>;
    for (const field of REQUIRED_EVENT_FIELDS) {
      if (typeof record[field] !== "string" || !record[field].trim()) throw new Error(`Event ${row}: "${field}" must be a non-empty string.`);
    }
    const timestamp = record.timestamp as string;
    const zonedIso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})$/i.test(timestamp);
    const [year, month, day] = timestamp.split("T", 1)[0].split("-").map(Number);
    const daysInMonth = month >= 1 && month <= 12 ? new Date(Date.UTC(year, month, 0)).getUTCDate() : 0;
    if (!zonedIso || day < 1 || day > daysInMonth || !Number.isFinite(Date.parse(timestamp))) throw new Error(`Event ${row}: "timestamp" must be a valid ISO 8601 date and time with a timezone.`);
    for (const field of OPTIONAL_STRING_FIELDS) {
      if (record[field] !== undefined && record[field] !== null && typeof record[field] !== "string") throw new Error(`Event ${row}: "${field}" must be a string or null.`);
    }
    const id = record.event_id as string;
    if (seenIds.has(id)) throw new Error(`Event ${row}: duplicate event_id "${id}".`);
    seenIds.add(id);
  });
  return events as SecurityEventInput[];
}

function parseAnalysisResponse(payload: unknown, submittedIds: Set<string>): AnalysisResponse {
  if (!payload || typeof payload !== "object") throw new Error("The API returned an invalid analysis response.");
  const result = payload as Partial<AnalysisResponse>;
  if (typeof result.summary !== "string" || typeof result.severity !== "string" || typeof result.confidence !== "number" || !Array.isArray(result.findings) || !Array.isArray(result.timeline) || !Array.isArray(result.recommended_actions) || !Array.isArray(result.limitations)) throw new Error("The API response is missing expected analysis fields.");
  for (const finding of result.findings) {
    if (!finding || typeof finding.title !== "string" || typeof finding.rationale !== "string" || typeof finding.severity !== "string" || typeof finding.confidence !== "number" || !Array.isArray(finding.evidence_event_ids) || finding.evidence_event_ids.some((id) => typeof id !== "string" || !submittedIds.has(id))) throw new Error("The API returned an invalid finding or evidence IDs that do not belong to the submitted events.");
  }
  if (result.timeline.some((event) => !event || typeof event.event_id !== "string" || !submittedIds.has(event.event_id) || typeof event.timestamp !== "string" || typeof event.event_type !== "string" || typeof event.source !== "string")) throw new Error("The API returned invalid timeline events or events that do not belong to the submitted input.");
  if (result.recommended_actions.some((item) => typeof item !== "string") || result.limitations.some((item) => typeof item !== "string")) throw new Error("The API returned invalid recommendations or limitations.");
  if (typeof result.investigation_id !== "string" || typeof result.created_at !== "string" || !["upload", "demo"].includes(result.source_type ?? "") || typeof result.event_count !== "number" || typeof result.events_retained !== "boolean") throw new Error("The API response is missing persistence metadata.");
  return result as AnalysisResponse;
}

function App() {
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [lastChecked, setLastChecked] = useState("Not checked yet");
  const [notice, setNotice] = useState("");
  const [investigationOpen, setInvestigationOpen] = useState(false);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadedEvents, setUploadedEvents] = useState<SecurityEventInput[] | null>(null);
  const [uploadError, setUploadError] = useState("");
  const [analysisSource, setAnalysisSource] = useState<AnalysisSource | null>(null);
  const [analysisEventCount, setAnalysisEventCount] = useState(0);
  const [history, setHistory] = useState<InvestigationPage | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [historyPage, setHistoryPage] = useState(0);
  const [historySearch, setHistorySearch] = useState("");
  const [historySeverity, setHistorySeverity] = useState("");
  const [historySource, setHistorySource] = useState("");
  const [historyFrom, setHistoryFrom] = useState("");
  const [historyTo, setHistoryTo] = useState("");
  const [detail, setDetail] = useState<AnalysisResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [detailId, setDetailId] = useState("");
  const [timelineSearch, setTimelineSearch] = useState("");
  const [timelineOrder, setTimelineOrder] = useState<"oldest" | "newest">("oldest");
  const [rulesOpen, setRulesOpen] = useState(false);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rulesError, setRulesError] = useState("");
  const [deleteError, setDeleteError] = useState("");

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError("");
    const params = new URLSearchParams({ limit: "10", offset: String(historyPage * 10) });
    if (historySearch.trim()) params.set("search", historySearch.trim());
    if (historySeverity) params.set("severity", historySeverity);
    if (historySource) params.set("source_type", historySource);
    if (historyFrom) params.set("created_after", new Date(`${historyFrom}T00:00:00Z`).toISOString());
    if (historyTo) params.set("created_before", new Date(`${historyTo}T23:59:59Z`).toISOString());
    try {
      setHistory(await fetchInvestigations(params));
    } catch (error) {
      setHistoryError(error instanceof Error ? error.message : "Could not load investigation history.");
    } finally {
      setHistoryLoading(false);
    }
  }, [historyPage, historySearch, historySeverity, historySource, historyFrom, historyTo]);

  const visibleTimeline = useMemo(() => {
    if (!detail) return [];
    const query = timelineSearch.trim().toLowerCase();
    return detail.timeline
      .filter((event) => !query || [event.event_id, event.event_type, event.username, event.source_ip, event.source].some((value) => value?.toLowerCase().includes(query)))
      .slice()
      .sort((left, right) => {
        const delta = Date.parse(left.timestamp) - Date.parse(right.timestamp);
        return timelineOrder === "oldest" ? delta : -delta;
      });
  }, [detail, timelineSearch, timelineOrder]);

  const checkApi = useCallback(async () => {
    setApiStatus("checking");

    try {
      const payload = await apiRequest<HealthResponse>("/health");
      if (payload.status !== "ok") throw new Error("API is unhealthy");

      setApiStatus("online");
    } catch {
      setApiStatus("offline");
    } finally {
      setLastChecked(new Date().toLocaleTimeString());
    }
  }, []);

  useEffect(() => {
    void checkApi();
  }, [checkApi]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshHistory(), 250);
    return () => window.clearTimeout(timer);
  }, [refreshHistory]);

  useEffect(() => {
    const modal = document.querySelector<HTMLElement>('[role="dialog"][aria-modal="true"]');
    if (!modal) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    modal.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !analyzing) {
        setInvestigationOpen(false);
        setDetailOpen(false);
        setRulesOpen(false);
      }
      if (event.key !== "Tab") return;
      const items = Array.from(modal.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex="0"]'));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previouslyFocused?.focus();
    };
  }, [investigationOpen, detailOpen, rulesOpen, analyzing, detail, detailLoading]);

  const showNotice = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 3600);
  };

  const openInvestigation = () => {
    setAnalysisError("");
    setInvestigationOpen(true);
  };

  const selectLogFile = async (file?: File) => {
    setSelectedFile(file ?? null);
    setUploadedEvents(null);
    setUploadError("");
    setAnalysisError("");
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".json")) {
      setUploadError("Choose a .json file.");
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setUploadError("File is larger than the 5 MB limit.");
      return;
    }
    try {
      const value: unknown = JSON.parse(await file.text());
      setUploadedEvents(validateUploadedEvents(value));
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : "Could not read this JSON file.");
    }
  };

  const submitAnalysis = async (events: SecurityEventInput[], source: AnalysisSource) => {
    setAnalyzing(true);
    setAnalysisError("");
    setAnalysis(null);
    const submittedIds = new Set(events.map((event) => event.event_id));

    try {
      const payload = await apiRequest<unknown>("/investigations/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events, source_type: source }),
      });
      const result = parseAnalysisResponse(payload, submittedIds);
      setAnalysis(result);
      setAnalysisSource(source);
      setAnalysisEventCount(events.length);
      void refreshHistory();
    } catch (error) {
      setAnalysisError(
        error instanceof Error
          ? error.message
          : "Could not analyse these events.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const runSampleInvestigation = () => {
    const baseTime = Date.parse("2026-10-27T10:00:00+05:30");
    const events = Array.from({ length: 5 }, (_, index) => ({
      event_id: `demo-auth-${String(index + 1).padStart(3, "0")}`,
      timestamp: new Date(baseTime + index * 60_000).toISOString(),
      event_type: "authentication",
      source: "linux-auth",
      username: "demo-user",
      source_ip: index === 4 ? "203.0.113.43" : "203.0.113.42",
      outcome: index === 4 ? "success" : "failure",
      message: `Synthetic authentication event ${index + 1}`,
    }));
    return submitAnalysis(events, "demo");
  };

  const openInvestigationDetails = async (id: string) => {
    setDetail(null);
    setDetailId(id);
    setDetailOpen(true);
    setDetailLoading(true);
    setDetailError("");
    try {
      setDetail(await fetchInvestigation(id));
    } catch (error) {
      setDetailError(error instanceof Error ? error.message : "Could not load investigation details.");
    } finally {
      setDetailLoading(false);
    }
  };

  const removeInvestigation = async (item: InvestigationSummary) => {
    if (!window.confirm(`Delete investigation ${item.investigation_id}? Its retained event evidence will also be deleted.`)) return;
    setDeleteError("");
    try {
      await deleteInvestigation(item.investigation_id);
      if (detail?.investigation_id === item.investigation_id) setDetail(null);
      if (history?.items.length === 1 && historyPage > 0) setHistoryPage((page) => page - 1);
      await refreshHistory();
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : "Could not delete investigation.");
    }
  };

  const exportDetail = () => {
    if (!detail) return;
    const blob = new Blob([JSON.stringify(detail, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `luna-investigation-${detail.investigation_id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const openRules = async () => {
    setRulesOpen(true);
    setRulesLoading(true);
    setRulesError("");
    try {
      setRules(await fetchDetectionRules());
    } catch (error) {
      setRulesError(error instanceof Error ? error.message : "Could not load configured detection rules.");
    } finally {
      setRulesLoading(false);
    }
  };

  const statusLabel =
    apiStatus === "online"
      ? "API connected"
      : apiStatus === "offline"
        ? "API unavailable"
        : "Connecting to API";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={22} strokeWidth={2.2} />
          </div>
          <div>
            <div className="brand-name">
              Luna<span>.</span>
            </div>
            <div className="brand-caption">SECURITY INTELLIGENCE</div>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="nav-group" aria-label="Primary navigation">
          <button
            className="nav-item active"
            onClick={() => showNotice("You're already on the Overview page.")}
          >
            <Gauge size={17} />
            <span>Overview</span>
            <span className="nav-indicator" />
          </button>
          <button className="nav-item" onClick={openInvestigation}>
            <FileSearch size={17} />
            <span>Investigations</span>
            <span className="nav-count">{analysis ? 1 : 0}</span>
          </button>
          <button
            className="nav-item"
            onClick={() => showNotice("Incident management is not implemented yet.")}
          >
            <ShieldAlert size={17} />
            <span>Incidents</span>
          </button>
          <button
            className="nav-item"
            onClick={() => document.getElementById("investigation-history")?.scrollIntoView({ behavior: "smooth" })}
          >
            <Network size={17} />
            <span>Event explorer</span>
          </button>
          <button className="nav-item" onClick={() => void openRules()}>
            <Radar size={17} />
            <span>Detection rules</span>
          </button>
        </nav>

        <div className="workspace-label tools-label">SYSTEM</div>
        <nav className="nav-group" aria-label="System navigation">
          <button
            className="nav-item"
            onClick={() => showNotice("Integrations are not configured yet.")}
          >
            <Layers3 size={17} />
            <span>Integrations</span>
          </button>
          <button
            className="nav-item"
            onClick={() => showNotice("Settings are not available yet.")}
          >
            <Settings2 size={17} />
            <span>Settings</span>
          </button>
        </nav>

        <div className="sidebar-spacer" />
        <div className="sidebar-status">
          <div className="status-orb">
            <Sparkles size={16} />
          </div>
          <div className="sidebar-status-copy">
            <strong>Luna Agent</strong>
            <span>Rule-based prototype</span>
          </div>
          <span className="pending-dot" />
        </div>
        <div className="profile-row">
          <div className="avatar">M</div>
          <div className="profile-copy">
            <strong>Mugu</strong>
            <span>Project admin</span>
          </div>
          <ChevronDown size={15} className="muted-icon" />
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Workspace</span>
            <span className="crumb-slash">/</span>
            <strong>Overview</strong>
          </div>
          <div className="topbar-actions">
            <div className={`connection-pill ${apiStatus}`}>
              {apiStatus === "online" ? (
                <Wifi size={14} />
              ) : apiStatus === "offline" ? (
                <WifiOff size={14} />
              ) : (
                <Activity size={14} />
              )}
              <span>{statusLabel}</span>
            </div>
            <button
              className="icon-button"
              aria-label="Search"
              onClick={() => showNotice("Search is not implemented yet.")}
            >
              <Search size={17} />
            </button>
            <button
              className="icon-button notification-button"
              aria-label="Notifications"
              onClick={() => showNotice("No notifications yet.")}
            >
              <Bell size={17} />
              <i />
            </button>
            <div className="topbar-avatar">M</div>
          </div>
        </header>

        <div className="page-content">
          <section className="hero-row">
            <div>
              <div className="eyebrow">
                <span className="eyebrow-line" />
                SECURITY OPERATIONS CENTER
              </div>
              <h1>
                Good to have you back, <span>Mugu.</span>
              </h1>
              <p className="hero-subtitle">
                Your security workspace, ready for its next investigation.
              </p>
            </div>
            <div className="hero-actions">
              <button
                className="button button-secondary"
                onClick={() => void checkApi()}
              >
                <RefreshCw size={15} />
                Refresh status
              </button>
              <button
                className="button button-primary"
                onClick={openInvestigation}
              >
                <Plus size={17} />
                New investigation
              </button>
            </div>
          </section>

          <section className="notice-banner">
            <div className="notice-icon">
              <LockKeyhole size={18} />
            </div>
            <div className="notice-copy">
              <strong>Detection prototype · v0.2.0</strong>
              <span>Current detection: repeated failed authentication attempts for the same username and source IP within five minutes.</span>
            </div>
            <div className="banner-tag">
              <span />
              DEVELOPMENT
            </div>
          </section>

          <section className="metric-grid" aria-label="Workspace metrics">
            <MetricCard
              icon={<FileSearch size={18} />}
              label="Investigations"
              value={history ? String(history.total) : "—"}
              detail={historyLoading ? "Loading saved history" : historyError ? "History unavailable" : "Matching saved records"}
              tone="blue"
              trend="—"
            />
            <MetricCard
              icon={<ShieldAlert size={18} />}
              label="Findings"
              value={history ? String(history.items.reduce((sum, item) => sum + item.finding_count, 0)) : "—"}
              detail={history ? "Findings on this page" : "History unavailable"}
              tone="amber"
              trend="—"
            />
            <MetricCard
              icon={<Activity size={18} />}
              label="Events analysed"
              value={history ? String(history.items.reduce((sum, item) => sum + item.event_count, 0)) : "—"}
              detail={history ? "Events on this page" : "History unavailable"}
              tone="violet"
              trend="—"
            />
            <MetricCard
              icon={<ShieldCheck size={18} />}
              label="API health"
              value={apiStatus === "online" ? "Online" : apiStatus === "offline" ? "Offline" : "Checking"}
              detail={lastChecked}
              tone="green"
              trend={apiStatus === "online" ? "OK" : "—"}
            />
          </section>

          <section className="dashboard-grid">
            <div className="panel activity-panel">
              <div className="panel-header">
                <div>
                  <div className="panel-kicker">ACTIVITY</div>
                  <h2>Investigation activity</h2>
                </div>
                <span className="subtle-select">Latest analysis</span>
              </div>
              <div className="empty-chart">
        <div className="chart-grid-lines" aria-hidden="true" />
                <div className="chart-center">
                  <div className="chart-icon">
                    <Activity size={23} />
                  </div>
                  <strong>{historyLoading ? "Loading saved investigations" : historyError ? "Investigation history unavailable" : history?.items[0]?.summary ?? "No saved investigations yet"}</strong>
                  <span>
                    {historyError || (history?.items[0] ? `${history.items[0].event_count} events · ${history.items[0].severity} severity · saved ${new Date(history.items[0].created_at).toLocaleString()}` : "Upload JSON logs or run the synthetic demonstration. Saved history stays on this device until deleted.")}
                  </span>
                </div>
              </div>
            </div>

            <div className="panel status-panel">
              <div className="panel-header">
                <div>
                  <div className="panel-kicker">PLATFORM</div>
                  <h2>System status</h2>
                </div>
                <span className="live-label">
                  <span />
                  LIVE CHECK
                </span>
              </div>
              <div className="system-list">
                <SystemRow
                  icon={<TerminalSquare size={17} />}
                  name="FastAPI backend"
                  detail={lastChecked}
                  status={apiStatus}
                  onRefresh={() => void checkApi()}
                />
                <SystemRow
                  icon={<Sparkles size={17} />}
                  name="Investigation agent"
                  detail="Rule-based detection"
                  status={apiStatus === "online" ? "online" : "pending"}
                />
                <SystemRow
                  icon={<Layers3 size={17} />}
                  name="SQLite investigation history"
                  detail="Local database · event retention enabled by default"
                  status={apiStatus === "online" ? "online" : "pending"}
                />
                <SystemRow
                  icon={<Fingerprint size={17} />}
                  name="Detection engine"
                  detail="Four deterministic authentication rules"
                  status={apiStatus === "online" ? "online" : "pending"}
                />
              </div>
              <div className="system-footer">
                <span>Last health check</span>
                <strong>{lastChecked}</strong>
              </div>
            </div>
          </section>

          <section className="panel incidents-panel" id="investigation-history">
            <div className="panel-header">
              <div>
                <div className="panel-kicker">INVESTIGATIONS</div>
                <h2>Saved investigation history</h2>
              </div>
              <div className="history-actions">
                <button className="icon-button" aria-label="Refresh investigation history" disabled={historyLoading} onClick={() => void refreshHistory()}><RefreshCw size={15} /></button>
                <button className="text-button" onClick={openInvestigation}>Run analysis <ArrowUpRight size={15} /></button>
              </div>
            </div>
            <div className="history-filters">
              <label>Search summary<input value={historySearch} onChange={(event) => { setHistoryPage(0); setHistorySearch(event.target.value); }} placeholder="Search saved analyses" /></label>
              <label>Severity<select value={historySeverity} onChange={(event) => { setHistoryPage(0); setHistorySeverity(event.target.value); }}><option value="">All severities</option><option value="unknown">Unknown</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
              <label>Source<select value={historySource} onChange={(event) => { setHistoryPage(0); setHistorySource(event.target.value); }}><option value="">All sources</option><option value="upload">Uploaded logs</option><option value="demo">Synthetic demo</option></select></label>
              <label>From<input type="date" value={historyFrom} onChange={(event) => { setHistoryPage(0); setHistoryFrom(event.target.value); }} /></label>
              <label>To<input type="date" value={historyTo} onChange={(event) => { setHistoryPage(0); setHistoryTo(event.target.value); }} /></label>
            </div>
            {deleteError && <div role="alert" className="analysis-error history-error">{deleteError}</div>}
            {historyError && <div role="alert" className="analysis-error history-error">{historyError}<button className="button button-secondary compact" onClick={() => void refreshHistory()}>Retry</button></div>}
            {historyLoading && !history && <div className="history-empty" role="status">Loading investigation history…</div>}
            {!historyLoading && history && history.items.length === 0 && <div className="history-empty">{history.total ? "No saved investigations match these filters." : "No investigations have been saved yet. Start with an upload or synthetic demonstration."}</div>}
            {history && history.items.length > 0 && <div className="history-list">
              {history.items.map((item) => <article className="history-row" key={item.investigation_id}>
                <div className="history-row-main"><span className={`severity-tag ${item.severity}`}>{item.severity}</span><strong>{item.summary}</strong><span className="history-metadata">{new Date(item.created_at).toLocaleString()} · {item.event_count} events · {item.finding_count} findings · {item.source_type === "demo" ? "Synthetic demo" : "Uploaded logs"}</span></div>
                <div className="history-row-actions"><button className="button button-secondary compact" onClick={() => void openInvestigationDetails(item.investigation_id)}>Review</button><button className="icon-button danger-button" aria-label={`Delete investigation ${item.investigation_id}`} onClick={() => void removeInvestigation(item)}><Trash2 size={15} /></button></div>
              </article>)}
              <div className="history-pagination"><span>{history.total} investigation(s) · page {historyPage + 1} of {Math.max(1, Math.ceil(history.total / history.limit))}</span><div><button className="button button-secondary compact" disabled={historyPage === 0 || historyLoading} onClick={() => setHistoryPage((page) => Math.max(0, page - 1))}>Previous</button><button className="button button-secondary compact" disabled={(historyPage + 1) * history.limit >= history.total || historyLoading} onClick={() => setHistoryPage((page) => page + 1)}>Next</button></div></div>
            </div>}
          </section>

          <footer className="page-footer">
            <span>
              <Command size={13} />
              Luna <span className="footer-divider">/</span> Threat
              Intelligence &amp; Investigation Agent
            </span>
            <span>
              Prototype v0.3.0 <span className="footer-divider">·</span>{" "}
              Local SQLite investigation history
            </span>
          </footer>
        </div>
      </main>

      {investigationOpen && (
        <div className="investigation-backdrop">
          <section
            className="investigation-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="investigation-title"
            tabIndex={-1}
          >
            <div className="investigation-modal-header">
              <div>
                <div className="panel-kicker">SECURITY ANALYSIS</div>
                <h2 id="investigation-title">New investigation</h2>
                <p className="investigation-description">Upload JSON security events from your device or try the synthetic demo. Files are read in your browser and sent only to the configured Luna API.</p>
              </div>
              <button
                className="icon-button"
                aria-label="Close investigation"
                disabled={analyzing}
                onClick={() => setInvestigationOpen(false)}
              >
                ×
              </button>
            </div>

            <div className="demo-notice">
              <ShieldCheck size={17} />
              <span>Only the sample option uses synthetic data. Uploaded events go to your configured Luna API and are retained in local SQLite by default until deleted. Set LUNA_STORE_RAW_EVENTS=false to disable raw event retention.</span>
            </div>

            <div className="upload-section">
              <label className="upload-label" htmlFor="security-log-file">Upload JSON security logs</label>
              <p className="result-muted">Choose a JSON array of events or an object with an “events” array. Maximum 5 MB and 10,000 events.</p>
              <input id="security-log-file" className="file-input" type="file" accept=".json,application/json" aria-describedby="upload-help upload-feedback" onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; void selectLogFile(file); }} />
              <div id="upload-help" className="upload-help">Required: event_id, timestamp with timezone, event_type, and source. Optional fields must be strings or null.</div>
              {selectedFile && <div className="file-selection"><strong>{selectedFile.name}</strong><span>{uploadedEvents ? `${uploadedEvents.length.toLocaleString()} events validated` : `${(selectedFile.size / 1024).toFixed(1)} KB`}</span></div>}
              <div id="upload-feedback" className={uploadError ? "analysis-error" : "upload-valid"} role={uploadError ? "alert" : "status"} aria-live="polite">{uploadError || (uploadedEvents ? "File validated and ready for analysis." : "Choose a JSON file to validate it in your browser.")}</div>
              <button className="button button-primary" disabled={!uploadedEvents || analyzing} onClick={() => uploadedEvents && void submitAnalysis(uploadedEvents, "upload")}>
                <Upload size={15} />{analyzing ? "Analysing…" : "Analyse uploaded logs"}
              </button>
            </div>

            {analysisError && (
              <div className="analysis-error" role="alert">
                <strong>Analysis failed</strong>
                <span>{analysisError}</span>
                <span>
                  Check that the FastAPI backend is running and reachable.
                </span>
              </div>
            )}

            {!analysis && !analysisError && !uploadedEvents && (
              <div className="analysis-preview">
                <div>
                  <span>Events</span>
                  <strong>5 synthetic events</strong>
                </div>
                <div>
                  <span>Scenario</span>
                  <strong>Repeated failed logins</strong>
                </div>
                <div>
                  <span>Source IP</span>
                  <strong>203.0.113.42 (documentation range)</strong>
                </div>
              </div>
            )}

            {analysis && (
              <div className="analysis-results" aria-live="polite">
                <div className="result-summary">
                  <span
                    className={`severity-tag ${analysis.severity.toLowerCase()}`}
                  >
                    {analysis.severity}
                  </span>
                  <strong>{analysis.summary}</strong>
                  <span>
                    Confidence: {(analysis.confidence * 100).toFixed(0)}%
                  </span>
                  <span className="source-badge">{analysisSource === "demo" ? "Synthetic demo data" : `User-provided logs · ${analysisEventCount.toLocaleString()} events`}</span>
                </div>

                <h3>Findings ({analysis.findings.length})</h3>

                {analysis.findings.length === 0 ? (
                  <p className="result-muted">
                    No configured detection rules matched these events.
                  </p>
                ) : (
                  analysis.findings.map((finding, index) => (
                    <article
                      className="finding-card"
                      key={`${finding.title}-${index}`}
                    >
                      <div className="finding-title">
                        <ShieldAlert size={16} />
                        <strong>{finding.title}</strong>
                        <span
                          className={`severity-tag ${finding.severity.toLowerCase()}`}
                        >
                          {finding.severity}
                        </span>
                      </div>
                      <p>{finding.rationale}</p>
                      <span className="result-muted">Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                      <div className="evidence-list">
                        <strong>Evidence event IDs</strong>
                        {finding.evidence_event_ids.map((id) => (
                          <code key={id}>{id}</code>
                        ))}
                      </div>
                    </article>
                  ))
                )}

                <h3>Event timeline ({analysis.timeline.length})</h3>
                <div className="timeline-list">
                  {analysis.timeline.map((event) => (
                    <div className="timeline-row" key={event.event_id}>
                      <code>{event.event_id}</code>
                      <span>
                        {event.event_type} · {event.source}
                      </span>
                      <time>
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </time>
                    </div>
                  ))}
                </div>

                {analysis.recommended_actions.length > 0 && (
                  <>
                    <h3>Recommended actions</h3>
                    <ul className="result-list">
                      {analysis.recommended_actions.map((action) => (
                        <li key={action}>{action}</li>
                      ))}
                    </ul>
                  </>
                )}

                <h3>Limitations</h3>
                <ul className="result-list">
                  {analysis.limitations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="investigation-modal-actions">
              <button
                className="button button-secondary"
                disabled={analyzing}
                onClick={() => setInvestigationOpen(false)}
              >
                Close
              </button>
              <button
                className="button button-primary"
                disabled={analyzing}
                onClick={() => void runSampleInvestigation()}
              >
                {analyzing ? (
                  <RefreshCw size={15} />
                ) : (
                  <Radar size={15} />
                )}
                {analyzing ? "Analysing…" : "Run sample analysis"}
              </button>
            </div>
          </section>
        </div>
      )}

      {detailOpen && (
        <div className="investigation-backdrop">
          <section className="investigation-modal detail-modal" role="dialog" aria-modal="true" aria-labelledby="detail-title" tabIndex={-1}>
            <div className="investigation-modal-header"><div><div className="panel-kicker">SAVED INVESTIGATION</div><h2 id="detail-title">Investigation details</h2><p className="investigation-description">Review the stored analysis and retained source events.</p></div><button className="icon-button" aria-label="Close investigation details" onClick={() => setDetailOpen(false)}><X size={17} /></button></div>
            {detailLoading && <div className="history-empty" role="status">Loading investigation details…</div>}
            {detailError && <div className="analysis-error" role="alert">{detailError}<button className="button button-secondary compact" onClick={() => void openInvestigationDetails(detailId)}>Retry</button></div>}
            {detail && <div className="analysis-results">
              <div className="result-summary"><span className={`severity-tag ${detail.severity}`}>{detail.severity}</span><strong>{detail.summary}</strong><span>Confidence: {(detail.confidence * 100).toFixed(0)}%</span><span className="source-badge">{detail.source_type === "demo" ? "Synthetic demo" : "User-provided logs"} · {detail.event_count} events · {new Date(detail.created_at).toLocaleString()}</span><span className="result-muted">Investigation ID: {detail.investigation_id}</span></div>
              <div className="history-actions"><strong>Findings ({detail.findings.length})</strong><button className="button button-secondary compact" onClick={exportDetail}><Download size={14} />Export JSON</button></div>
              {detail.findings.length === 0 ? <p className="result-muted">No configured rule matched this event set.</p> : detail.findings.map((finding, index) => <article className="finding-card" key={`${finding.title}-${index}`}><div className="finding-title"><ShieldAlert size={16} /><strong>{finding.title}</strong><span className={`severity-tag ${finding.severity}`}>{finding.severity}</span></div><p>{finding.rationale}</p><span className="result-muted">Confidence: {(finding.confidence * 100).toFixed(0)}%</span><div className="evidence-list"><strong>Evidence events</strong>{finding.evidence_event_ids.map((id) => <a href={`#event-${encodeURIComponent(id)}`} key={id}><code>{id}</code></a>)}</div></article>)}
              <h3>Event explorer ({visibleTimeline.length} of {detail.timeline.length})</h3><div className="timeline-tools"><label>Filter timeline<input value={timelineSearch} onChange={(event) => setTimelineSearch(event.target.value)} placeholder="ID, type, username, or source IP" /></label><label>Order<select value={timelineOrder} onChange={(event) => setTimelineOrder(event.target.value as "oldest" | "newest")}><option value="oldest">Oldest first</option><option value="newest">Newest first</option></select></label></div><div className="timeline-list">{visibleTimeline.map((event) => <div className="timeline-row" id={`event-${encodeURIComponent(event.event_id)}`} key={event.event_id}><code>{event.event_id}</code><span>{event.event_type} · {event.source}{event.username ? ` · ${event.username}` : ""}{event.source_ip ? ` · ${event.source_ip}` : ""}{event.outcome ? ` · ${event.outcome}` : ""}</span><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time></div>)}</div>
              {detail.events_retained ? <><h3>Retained input evidence ({detail.events?.length ?? 0} events)</h3><div className="event-evidence">{(detail.events ?? []).map((event) => <details key={String(event.event_id)}><summary><code>{String(event.event_id)}</code> · {String(event.event_type)} · {String(event.timestamp)}</summary><pre>{JSON.stringify(event, null, 2)}</pre></details>)}</div></> : <p className="result-muted">Raw event retention was disabled for this investigation.</p>}
              {detail.recommended_actions.length > 0 && <><h3>Recommended actions</h3><ul className="result-list">{detail.recommended_actions.map((action) => <li key={action}>{action}</li>)}</ul></>}
              <h3>Limitations</h3><ul className="result-list">{detail.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
            </div>}
            <div className="investigation-modal-actions"><button className="button button-secondary" onClick={() => setDetailOpen(false)}>Close</button></div>
          </section>
        </div>
      )}

      {rulesOpen && <div className="investigation-backdrop"><section className="investigation-modal rules-modal" role="dialog" aria-modal="true" aria-labelledby="rules-title" tabIndex={-1}><div className="investigation-modal-header"><div><div className="panel-kicker">DETECTION ENGINE</div><h2 id="rules-title">Configured authentication rules</h2><p className="investigation-description">Live thresholds from the backend configuration. These deterministic indicators do not prove compromise.</p></div><button className="icon-button" aria-label="Close detection rules" onClick={() => setRulesOpen(false)}><X size={17} /></button></div><div className="rule-list">{rulesLoading && <p role="status" className="result-muted">Loading configured rules…</p>}{rulesError && <div className="analysis-error" role="alert">{rulesError}<button className="button button-secondary compact" onClick={() => void openRules()}>Retry</button></div>}{rules.map((rule) => <article key={rule.id}><strong>{rule.name}</strong><span>{rule.description} Threshold: {rule.threshold} · Window: {rule.window_minutes} minutes · Severity: {rule.severity} · confidence label {(rule.confidence * 100).toFixed(0)}%.</span></article>)}<p className="result-muted">Confidence values are fixed rule-strength labels, not statistically calibrated probabilities. Exact window boundaries are inclusive.</p></div><div className="investigation-modal-actions"><button className="button button-secondary" onClick={() => setRulesOpen(false)}>Close</button></div></section></div>}

      {notice && (
        <div role="status" className="toast">
          <CheckCircle2 size={17} />
          {notice}
        </div>
      )}
    </div>
  );
}

function MetricCard({
  icon,
  label,
  value,
  detail,
  tone,
  trend,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  detail: string;
  tone: string;
  trend: string;
}) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <div className={`metric-icon ${tone}`}>{icon}</div>
        <span className="metric-trend">{trend}</span>
      </div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

function SystemRow({
  icon,
  name,
  detail,
  status,
  onRefresh,
}: {
  icon: ReactNode;
  name: string;
  detail: string;
  status: ApiStatus | "pending";
  onRefresh?: () => void;
}) {
  const label =
    status === "online"
      ? "Online"
      : status === "offline"
        ? "Offline"
        : status === "checking"
          ? "Checking"
          : "Pending";

  return (
    <div className="system-row">
      <div className="system-icon">{icon}</div>
      <div className="system-copy">
        <strong>{name}</strong>
        <span>{detail}</span>
      </div>
      <div className={`system-status ${status}`}>
        <i />
        {label}
      </div>
      {onRefresh && (
        <button
          className="mini-refresh"
          onClick={onRefresh}
          aria-label="Refresh backend status"
        >
          <RefreshCw size={13} />
        </button>
      )}
    </div>
  );
}

export default App;
