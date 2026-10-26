import type { CheckResult, ScanReport } from "./types";
import { fetchPage } from "./fetcher";
import { ALLOW_PRIVATE, assertPublicHost } from "./ssrf";
import { checkHttps } from "./checks/transport";
import { checkHeaders } from "./checks/headers";
import { checkCookies } from "./checks/cookies";
import { checkDns } from "./checks/dns";
import { checkExposure } from "./checks/exposure";
import { checkMixedContent } from "./checks/content";
import { detectPhp } from "./checks/php-detect";

export function normalizeTarget(input: string): URL {
  let s = input.trim();
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("http / https のみ対応しています");
  if (!ALLOW_PRIVATE && u.port && !["80", "443"].includes(u.port)) throw new Error("標準ポート (80/443) のみ対応しています");
  return u;
}

export async function scan(input: string): Promise<ScanReport> {
  const started = Date.now();
  const target = normalizeTarget(input);
  await assertPublicHost(target.hostname);

  let page = await fetchPage(target.toString());
  if (page.error && target.protocol === "https:") {
    // HTTPS で繋がらない場合は HTTP を試す
    const httpPage = await fetchPage(target.toString().replace(/^https:/, "http:"));
    if (!httpPage.error) page = httpPage;
  }
  if (page.error) throw new Error(`サイトに接続できませんでした: ${page.error}`);

  const final = new URL(page.finalUrl);
  // リダイレクト先が内部ネットワークでないことも確認
  await assertPublicHost(final.hostname);
  const isHttps = final.protocol === "https:";

  const [transport, dnsRes, exposure] = await Promise.all([
    checkHttps(page, final.hostname, final.host),
    checkDns(final.hostname),
    checkExposure(final.origin),
  ]);
  const headers = checkHeaders(page.headers, isHttps);
  const cookies = checkCookies(page.headers, isHttps);
  const mixed = checkMixedContent(page.body, isHttps);
  const php = await detectPhp(page, final.origin, exposure[0]?.evidence);

  const results: CheckResult[] = [
    ...php.results,
    ...transport,
    ...headers,
    ...cookies,
    ...exposure,
    ...mixed,
    ...dnsRes,
  ];

  const scored = results.filter((r) => r.status !== "unknown");
  const total = scored.reduce((n, r) => n + r.weight, 0);
  const got = scored.reduce((n, r) => n + r.score, 0);
  let totalScore = total ? Math.round((got / total) * 100) : 0;

  // 重大な PHP 脆弱性がある場合は上限を設ける
  if (php.assessment.verdict === "vulnerable" || php.assessment.verdict === "eol") {
    totalScore = Math.min(totalScore, 39);
  }
  if (exposure[0]?.status === "fail") totalScore = Math.min(totalScore, 49);

  return {
    target: target.toString(),
    finalUrl: page.finalUrl,
    scannedAt: new Date().toISOString(),
    totalScore,
    grade: toGrade(totalScore),
    results,
    php: php.assessment,
    durationMs: Date.now() - started,
  };
}

export function toGrade(s: number): ScanReport["grade"] {
  if (s >= 90) return "A";
  if (s >= 75) return "B";
  if (s >= 60) return "C";
  if (s >= 40) return "D";
  return "F";
}
