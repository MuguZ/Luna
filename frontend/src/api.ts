export type Finding = {
  title: string;
  rationale: string;
  severity: string;
  confidence: number;
  evidence_event_ids: string[];
  recommended_actions: string[];
};

export type TimelineEvent = {
  event_id: string;
  timestamp: string;
  event_type: string;
  source: string;
  username?: string | null;
  source_ip?: string | null;
  outcome?: string | null;
};

export type AnalysisResponse = {
  investigation_id: string;
  created_at: string;
  source_type: "upload" | "demo";
  event_count: number;
  events_retained: boolean;
  events?: Record<string, unknown>[];
  summary: string;
  severity: string;
  confidence: number;
  findings: Finding[];
  timeline: TimelineEvent[];
  recommended_actions: string[];
  limitations: string[];
};

export type InvestigationSummary = {
  investigation_id: string;
  created_at: string;
  source_type: "upload" | "demo";
  event_count: number;
  summary: string;
  severity: string;
  confidence: number;
  finding_count: number;
};

export type InvestigationPage = {
  items: InvestigationSummary[];
  total: number;
  limit: number;
  offset: number;
};

export type DetectionRule = {
  id: string;
  name: string;
  threshold: number;
  window_minutes: number;
  severity: string;
  confidence: number;
  description: string;
};

const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, init);
  } catch {
    throw new Error("Could not reach the SREEMA API. Check that the backend is running.");
  }
  const text = await response.text();
  let payload: unknown;
  try {
    payload = text ? JSON.parse(text) : undefined;
  } catch {
    if (response.ok) throw new Error("The API returned a response that was not valid JSON.");
    throw new Error(`The API returned an error (${response.status}) with an invalid response body.`);
  }
  if (!response.ok) {
    const detail = payload && typeof payload === "object" && "detail" in payload
      ? (payload as { detail: unknown }).detail
      : undefined;
    const description = typeof detail === "string"
      ? detail
      : Array.isArray(detail)
        ? detail.map((item) => item && typeof item === "object" && "msg" in item ? String(item.msg) : "Invalid request").join("; ")
        : undefined;
    throw new Error(description || `Request failed (${response.status}).`);
  }
  return payload as T;
}

export async function fetchInvestigations(params: URLSearchParams): Promise<InvestigationPage> {
  const query = params.toString();
  return apiRequest<InvestigationPage>(`/investigations${query ? `?${query}` : ""}`);
}

export function fetchInvestigation(id: string): Promise<AnalysisResponse> {
  return apiRequest<AnalysisResponse>(`/investigations/${encodeURIComponent(id)}`);
}

export function deleteInvestigation(id: string): Promise<void> {
  return apiRequest<void>(`/investigations/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function fetchDetectionRules(): Promise<DetectionRule[]> {
  return apiRequest<DetectionRule[]>("/detection-rules");
}
