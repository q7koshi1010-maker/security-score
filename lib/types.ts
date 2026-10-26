export type Status = "pass" | "warn" | "fail" | "info" | "unknown";

export interface CheckResult {
  id: string;
  category: string;
  title: string;
  status: Status;
  /** 0〜weight の得点 */
  score: number;
  weight: number;
  detail: string;
  advice?: string;
  evidence?: string;
}

export interface ScanReport {
  target: string;
  finalUrl: string;
  scannedAt: string;
  totalScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
  results: CheckResult[];
  php: PhpAssessment;
  durationMs: number;
}

export interface PhpAssessment {
  detected: boolean;
  version: string | null;
  evidence: string[];
  verdict: "vulnerable" | "eol" | "unknown" | "patched" | "not-php";
  summary: string;
  advisories: AdvisoryMatch[];
}

export interface AdvisoryMatch {
  id: string;
  title: string;
  severity: string;
  affected: boolean | null;
  note: string;
}
