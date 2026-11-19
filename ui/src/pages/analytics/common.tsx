// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Shared helpers and DTO interfaces for the dedicated analytics pages.
import { enc, get, qs } from "../../api";
import { useAsync } from "../../ui";

export interface AssetMatch {
  name: string;
  criticality: string;
}

export interface AttackTactic {
  id: string;
  name: string;
}

export interface TechniqueStat {
  id: string;
  name: string;
  tactics: string[];
  primaryEvents: number;
  secondaryEvents: number;
  sources: number;
  lastSeen: string;
  triggers: string[];
}

export interface SourceProfile {
  source: string;
  events: number;
  decoys: number;
  firstSeen: string;
  lastSeen: string;
  isIp: boolean;
  internal: boolean;
  whitelisted: boolean;
  knownScanner: boolean;
  asset: AssetMatch | null;
}

export function DaysSelect({ days, onChange }: { days: number; onChange: (d: number) => void }) {
  return (
    <label class="inline-field">
      <span>Window</span>
      <select class="input" value={String(days)} onChange={(e) => onChange(Number(e.currentTarget.value))}>
        {[1, 7, 30, 90, 365].map((d) => (
          <option key={d} value={d}>{d === 1 ? "24 hours" : `${d} days`}</option>
        ))}
      </select>
    </label>
  );
}

export function useProjection<T>(
  name: string,
  params: Record<string, string | number | boolean | undefined | null>,
) {
  const query = qs(params);
  return useAsync<T | undefined>(
    () => get<{ data: T }>(`/analytics/projections/${enc(name)}${query}`).then((r) => r.data),
    [name, query],
  );
}

export function criticalityKind(c: string): "bad" | "warn" | "info" | "neutral" {
  switch (c) {
    case "critical": return "bad";
    case "high": return "warn";
    case "medium": return "info";
    default: return "neutral";
  }
}
