import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  Activity,
  ArrowUpRight,
  Bell,
  BookOpen,
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
} from "lucide-react";

type ApiStatus = "checking" | "online" | "offline";

type HealthResponse = {
  status: string;
  service: string;
};

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

function App() {
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [lastChecked, setLastChecked] = useState<string>("Not checked yet");
  const [notice, setNotice] = useState("");

  const checkApi = useCallback(async () => {
    setApiStatus("checking");
    try {
      const response = await fetch(`${API_BASE_URL}/health`, { method: "GET" });
      if (!response.ok) throw new Error("API health check failed");
      const payload = (await response.json()) as HealthResponse;
      if (payload.status !== "ok") throw new Error("API did not report healthy status");
      setApiStatus("online");
      setLastChecked(new Date().toLocaleTimeString());
    } catch {
      setApiStatus("offline");
      setLastChecked(new Date().toLocaleTimeString());
    }
  }, []);

  useEffect(() => {
    void checkApi();
  }, [checkApi]);

  const showNotice = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 3600);
  };

  const statusLabel =
    apiStatus === "online" ? "API connected" : apiStatus === "offline" ? "API unavailable" : "Connecting to API";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={22} strokeWidth={2.2} /></div>
          <div>
            <div className="brand-name">SREEMA<span>.</span></div>
            <div className="brand-caption">SECURITY INTELLIGENCE</div>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="nav-group" aria-label="Primary navigation">
          <button className="nav-item active" onClick={() => showNotice("You're already on the Overview page.")}>
            <Gauge size={17} /><span>Overview</span><span className="nav-indicator" />
          </button>
          <button className="nav-item" onClick={() => showNotice("Investigation workspace is coming in the next milestone.")}>
            <FileSearch size={17} /><span>Investigations</span><span className="nav-count">0</span>
          </button>
          <button className="nav-item" onClick={() => showNotice("Incident views will be connected after the API is implemented.")}>
            <ShieldAlert size={17} /><span>Incidents</span><span className="nav-count">0</span>
          </button>
          <button className="nav-item" onClick={() => showNotice("Event explorer is planned for the ingestion milestone.")}>
            <Network size={17} /><span>Event explorer</span>
          </button>
          <button className="nav-item" onClick={() => showNotice("Detection rules are being designed with the agent module.")}>
            <Radar size={17} /><span>Detection rules</span>
          </button>
        </nav>

        <div className="workspace-label tools-label">SYSTEM</div>
        <nav className="nav-group" aria-label="System navigation">
          <button className="nav-item" onClick={() => showNotice("Integrations will be configured in a later milestone.")}>
            <Layers3 size={17} /><span>Integrations</span>
          </button>
          <button className="nav-item" onClick={() => showNotice("Settings are not available in this prototype yet.")}>
            <Settings2 size={17} /><span>Settings</span>
          </button>
        </nav>

        <div className="sidebar-spacer" />
        <div className="sidebar-status">
          <div className="status-orb"><Sparkles size={16} /></div>
          <div className="sidebar-status-copy">
            <strong>SREEMA Agent</strong>
            <span>Integration pending</span>
          </div>
          <span className="pending-dot" />
        </div>
        <div className="profile-row">
          <div className="avatar">M</div>
          <div className="profile-copy"><strong>Mugu</strong><span>Project admin</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>Overview</strong></div>
          <div className="topbar-actions">
            <div className={`connection-pill ${apiStatus}`}>
              {apiStatus === "online" ? <Wifi size={14} /> : apiStatus === "offline" ? <WifiOff size={14} /> : <Activity size={14} />}
              <span>{statusLabel}</span>
            </div>
            <button className="icon-button" aria-label="Search" onClick={() => showNotice("Search will be enabled when events are available.")}><Search size={17} /></button>
            <button className="icon-button notification-button" aria-label="Notifications" onClick={() => showNotice("No notifications yet.")}><Bell size={17} /><i /></button>
            <div className="topbar-avatar">M</div>
          </div>
        </header>

        <div className="page-content">
          <section className="hero-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS CENTER</div>
              <h1>Good to have you back, <span>Mugu.</span></h1>
              <p className="hero-subtitle">Your security workspace, ready for its first investigation.</p>
            </div>
            <div className="hero-actions">
              <button className="button button-secondary" onClick={() => void checkApi()}><RefreshCw size={15} /> Refresh status</button>
              <button className="button button-primary" onClick={() => showNotice("Investigation creation is coming after log ingestion and agent integration.")}><Plus size={17} /> New investigation</button>
            </div>
          </section>

          <section className="notice-banner">
            <div className="notice-icon"><LockKeyhole size={18} /></div>
            <div className="notice-copy">
              <strong>Foundation phase · v0.1.0</strong>
              <span>This dashboard is a UI scaffold. Detection counts and incident records will appear once log ingestion and the agent are connected.</span>
            </div>
            <div className="banner-tag"><span /> DEVELOPMENT</div>
          </section>

          <section className="metric-grid" aria-label="Workspace metrics">
            <MetricCard icon={<FileSearch size={18} />} label="Investigations" value="0" detail="No investigations yet" tone="blue" trend="—" />
            <MetricCard icon={<ShieldAlert size={18} />} label="Open incidents" value="0" detail="Awaiting event ingestion" tone="amber" trend="—" />
            <MetricCard icon={<Activity size={18} />} label="Events analysed" value="0" detail="No log sources connected" tone="violet" trend="—" />
            <MetricCard icon={<ShieldCheck size={18} />} label="Agent health" value="Pending" detail="Agent module not integrated" tone="green" trend="…" />
          </section>

          <section className="dashboard-grid">
            <div className="panel activity-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">ACTIVITY</div><h2>Investigation activity</h2></div>
                <button className="subtle-select" onClick={() => showNotice("Activity filters will be available when investigations are stored.")}>Last 7 days <ChevronDown size={14} /></button>
              </div>
              <div className="empty-chart">
                <div className="chart-grid-lines"><span /><span /><span /><span /></div>
                <div className="chart-center">
                  <div className="chart-icon"><Activity size={23} /></div>
                  <strong>Waiting for your first investigation</strong>
                  <span>Activity analytics will appear here when SREEMA starts analysing events.</span>
                </div>
                <div className="chart-axis"><span>MON</span><span>TUE</span><span>WED</span><span>THU</span><span>FRI</span><span>SAT</span><span>SUN</span></div>
              </div>
            </div>

            <div className="panel status-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">PLATFORM</div><h2>System status</h2></div>
                <span className="live-label"><span /> LIVE CHECK</span>
              </div>
              <div className="system-list">
                <SystemRow icon={<TerminalSquare size={17} />} name="FastAPI backend" detail={lastChecked} status={apiStatus} onRefresh={() => void checkApi()} />
                <SystemRow icon={<Sparkles size={17} />} name="Investigation agent" detail="Not integrated yet" status="pending" />
                <SystemRow icon={<Layers3 size={17} />} name="PostgreSQL" detail="Not configured yet" status="pending" />
                <SystemRow icon={<Fingerprint size={17} />} name="Detection engine" detail="In development" status="pending" />
              </div>
              <div className="system-footer"><span>Last health check</span><strong>{lastChecked}</strong></div>
            </div>
          </section>

          <section className="panel incidents-panel">
            <div className="panel-header">
              <div><div className="panel-kicker">INVESTIGATIONS</div><h2>Recent investigations</h2></div>
              <button className="text-button" onClick={() => showNotice("There are no saved investigations yet.")}>View all <ArrowUpRight size={15} /></button>
            </div>
            <div className="empty-table">
              <div className="empty-table-icon"><BookOpen size={21} /></div>
              <div><strong>No investigations to display</strong><span>Upload a synthetic or authorised security log once ingestion is implemented.</span></div>
              <button className="button button-secondary compact" onClick={() => showNotice("Log upload will be enabled in the next backend milestone.")}><Upload size={15} /> Upload logs</button>
            </div>
          </section>

          <footer className="page-footer">
            <span><Command size={13} /> SREEMA <span className="footer-divider">/</span> Threat Intelligence &amp; Investigation Agent</span>
            <span>Prototype v0.1.0 <span className="footer-divider">·</span> Read-only by design</span>
          </footer>
        </div>
      </main>
      {notice && <div role="status" className="toast"><CheckCircle2 size={17} />{notice}</div>}
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
      <div className="metric-top"><div className={`metric-icon ${tone}`}>{icon}</div><span className="metric-trend">{trend}</span></div>
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
  const label = status === "online" ? "Online" : status === "offline" ? "Offline" : status === "checking" ? "Checking" : "Pending";
  return (
    <div className="system-row">
      <div className="system-icon">{icon}</div>
      <div className="system-copy"><strong>{name}</strong><span>{detail}</span></div>
      <div className={`system-status ${status}`}><i />{label}</div>
      {onRefresh && <button className="mini-refresh" onClick={onRefresh} aria-label="Refresh backend status"><RefreshCw size={13} /></button>}
    </div>
  );
}

export default App;
