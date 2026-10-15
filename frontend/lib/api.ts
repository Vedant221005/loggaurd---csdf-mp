import axios from "axios";
import type { Analysis, EventPage, Finding, EventRecord } from "./types";
const api = axios.create({ baseURL: (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/api\/?$/, ""), timeout: 30000 });
const url = (path: string) => path.startsWith("/api") ? path : `/api${path}`;
export async function health() { return (await api.get(url("/health"))).data; }
export async function uploadLog(file: File, options?: { failedLoginThreshold?: number; windowMinutes?: number; serviceFailureThreshold?: number }) {
  const form = new FormData(); form.append("file", file);
  const params = { failed_login_threshold: options?.failedLoginThreshold || 5, window_minutes: options?.windowMinutes || 5, service_failure_threshold: options?.serviceFailureThreshold || 3 };
  return (await api.post<Analysis>(url("/analyze"), form, { params })).data;
}
export async function getAnalysis(id: string) { return (await api.get<Analysis>(url(`/analysis/${id}`))).data; }
export async function getEvents(id: string, params?: Record<string, string | number>) { return (await api.get<EventPage>(url(`/analysis/${id}/events`), { params })).data; }
export async function getFindings(id: string) { return (await api.get<{ items: Finding[] }>(url(`/analysis/${id}/findings`))).data.items; }
export async function getTimeline(id: string) { return (await api.get<{ items: EventRecord[] }>(url(`/analysis/${id}/timeline`))).data.items; }
export async function getHistory() { return (await api.get<{ items: Analysis[] }>(url("/history"))).data.items; }
export async function clearHistory() { await api.delete(url("/history")); }
export async function verifyHash(id: string, reference_sha256: string) { return (await api.post(url(`/analysis/${id}/verify-hash`), { reference_sha256 })).data; }
export function reportUrl(id: string, format: "json" | "txt") { return `${api.defaults.baseURL}${url(`/analysis/${id}/report/${format}`)}`; }
export function apiError(error: unknown) { if (axios.isAxiosError(error)) return error.response?.data?.detail || "The backend could not complete the request."; return "Unable to reach the LogGuard backend."; }
