/**
 * PHP の脆弱性データ。新しい脆弱性が出たらここに追記するだけで判定に反映される。
 * fixedIn: 各ブランチ(メジャー.マイナー)での修正版。ここに無いブランチは修正版が存在しない(EOL)扱い。
 */
export interface PhpAdvisory {
  id: string;
  title: string;
  severity: string;
  cvss: string;
  published: string;
  fixedIn: Record<string, string>;
  affectedFrom: string;
  reference: string;
  mitigation?: string;
}

export const PHP_ADVISORIES: PhpAdvisory[] = [
  {
    id: "CVE-2026-109618",
    title: "PHP2Shell: 認証なしリモートコード実行 (1/2)",
    severity: "緊急",
    cvss: "9.2 (CVSS v4.0)",
    published: "2026-10-21",
    affectedFrom: "5.4.0",
    fixedIn: { "8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35" },
    reference: "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/",
  },
  {
    id: "CVE-2026-109619",
    title: "PHP2Shell: 認証なしリモートコード実行 (2/2)",
    severity: "緊急",
    cvss: "9.2 (CVSS v4.0)",
    published: "2026-10-21",
    affectedFrom: "5.4.0",
    fixedIn: { "8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35" },
    reference: "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/",
  },
  {
    id: "CVE-2026-115560",
    title: "session.upload_progress 経由のコード実行リスク(修正版未公開)",
    severity: "注意",
    cvss: "未評価",
    published: "2026-10-23",
    affectedFrom: "5.4.0",
    fixedIn: {},
    reference: "https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html",
    mitigation: "php.ini で session.upload_progress.enabled=0 を設定する(次回の定期リリースで修正予定)",
  },
];

/** 2026-10 時点でセキュリティ修正が提供されるブランチ */
export const SUPPORTED_BRANCHES = ["8.2", "8.3", "8.4", "8.5"];

export function parseVersion(v: string): number[] | null {
  const m = v.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)];
}

export function compareVersion(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

export function branchOf(v: string): string | null {
  const p = parseVersion(v);
  return p ? `${p[0]}.${p[1]}` : null;
}
