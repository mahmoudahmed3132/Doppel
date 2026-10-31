// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Shapes of the admin API responses used by the UI (docs/openapi.yaml).

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Session { enrol_only: boolean; created_at: string; expires_at: string; idle_expires_at: string }
export interface MFAState { available: boolean; enabled: boolean; enrolment_pending: boolean; required: boolean; recovery_codes_remaining: number }

export interface Technique { id: string; name: string; tactics: string[] }
export interface Location { country_code: string; country: string; region: string; city: string; lat: number; lon: number; basis: string; address: string }
export interface EventRecord {
  seq: number; event_id: string; node_id: string; sensor_id: string; trigger: string; severity: Severity;
  occurred_at: string; received_at: string; source: string; target: string; details: unknown;
  read: boolean; archived: boolean; whitelisted: boolean; known_scanner: boolean; node_alias: string;
  enrichment: { attack?: { primary: Technique; secondary?: Technique[] }; source_asset?: { name: string; criticality: string }; location?: Location };
}

export interface NodeHealth { online: boolean; in_sync: boolean; sensors_total: number; sensors_online: number; sensors_offline: number; sensors_pending: number }
export interface NodeSummary {
  id: string; alias: string; tags: string[] | null; created_at: string; last_seen_at: string | null;
  desired_revision: string; applied_revision: string; health: NodeHealth;
}
export interface SensorView {
  node_id: string; id: string; catalogue_name: string; version: string; config: Record<string, string> | null;
  silenced: boolean; status: string; status_changed_at: string | null; last_heartbeat_at: string | null;
  last_activity_at: string | null; sdk_version: string; created_at: string;
  config_masked: string[]; latest_version?: string; update_available: boolean;
}
export interface NodeDetail extends NodeSummary { sensors: SensorView[] }

export interface CatalogueVersion { version: string; available: boolean; verified: boolean; deprecated: boolean; listed: boolean; reason?: string }
export interface CatalogueSensor { name: string; display_name: string; category: string; description: string; latest: string; versions: CatalogueVersion[] }
export interface CatalogueStatus { registry_url: string; last_refresh: string | null; last_error?: string }

export interface ConfigItem {
  name: string; type: "string" | "int" | "bool" | "enum" | "list" | "port" | "path";
  item_type?: string; default?: string; required?: boolean; secret?: boolean; hub_reserved?: boolean; description: string;
  validation?: { pattern?: string; min?: number; max?: number; enum?: string[]; max_items?: number; max_length?: number };
}
export interface Manifest {
  name: string; display_name: string; version: string; description: string; category: string; author?: string;
  documentation?: string; config: ConfigItem[]; triggers?: { name: string; default_severity: string; description: string }[];
}

export interface Settings {
  public_endpoint: string; registry_url: string; catalogue_refresh_hours: number; update_check_hours: number;
  retention: { archive_after_days: number; purge_archived_after_days: number; history_days: number };
  whitelist: string[] | null; known_scanners: string[] | null; source_lists_active: boolean;
}

export interface SystemStatus {
  version: string; schema: number; uptime_seconds: number; armed: boolean; siem_queue: { depth: number; dropped: number };
  updates: { latest_hub: string; latest_cli: string; last_check: string | null; last_error?: string };
  hub_update_available: boolean; cli_release_notice: boolean; cli_notice_ack: string;
  modules: { attack: boolean; projections: string[] }; live_clients: number;
}
