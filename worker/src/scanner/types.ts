// Scanner types (mirrors Python module output schema)

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  type: string;
  severity: Severity;
  url: string;
  description: string;
  replication_steps?: string[];
  remediation?: string;
  evidence?: string;
}

export interface ModuleResult {
  module: string;
  target: string;
  vulnerable: boolean;
  findings: Finding[];
  errors: string[];
  duration_ms: number;
}

export interface ModuleFn {
  (target: string, state?: ScanState): Promise<ModuleResult>;
}

export interface ScanState {
  verbose?: boolean;
  isWordPress?: boolean;
  reachabilityCache?: Map<string, { status: number; timestamp: number }>;
  responseCache?: Map<string, { status: number; body: string; headers: Record<string, string>; timestamp: number }>;
  signal?: AbortSignal;
  [key: string]: unknown;
}
