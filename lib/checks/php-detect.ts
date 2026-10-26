import type { CheckResult, PhpAssessment } from "../types";
import type { FetchedPage } from "../fetcher";
import { assessPhpVersion } from "../php";
import { probe } from "../fetcher";

/** 外部から PHP の利用とバージョンを推定する */
export async function detectPhp(
  page: FetchedPage,
  origin: string,
  exposureEvidence?: string
): Promise<{ assessment: PhpAssessment; results: CheckResult[]; modPhp: boolean | null }> {
  const evidence: string[] = [];
  let version: string | null = null;
  let detected = false;

  const xpb = page.headers.get("x-powered-by") ?? "";
  const xpbMatch = /PHP\/(\d+\.\d+(?:\.\d+)?)/i.exec(xpb);
  if (xpbMatch) {
    detected = true;
    version = xpbMatch[1];
    evidence.push(`X-Powered-By: ${xpb}`);
  } else if (/php/i.test(xpb)) {
    detected = true;
    evidence.push(`X-Powered-By: ${xpb}`);
  }

  const server = page.headers.get("server") ?? "";
  const srvMatch = /PHP\/(\d+\.\d+(?:\.\d+)?)/i.exec(server);
  if (srvMatch) {
    detected = true;
    version = version ?? srvMatch[1];
    evidence.push(`Server: ${server}`);
  }
  const modPhp = /apache/i.test(server) ? (srvMatch ? true : null) : null;

  const cookies = page.headers.getSetCookie ? page.headers.getSetCookie() : [];
  if (cookies.some((c) => /^PHPSESSID=/i.test(c))) {
    detected = true;
    evidence.push("Set-Cookie: PHPSESSID");
  }

  if (/\.php(\?|"|'|\s|$)/i.test(page.finalUrl) || /href=["'][^"']*\.php/i.test(page.body)) {
    detected = true;
    evidence.push(".php の URL");
  }

  const isWp = /wp-content\/|wp-includes\//i.test(page.body) || /<meta name="generator" content="WordPress/i.test(page.body);
  if (isWp) {
    detected = true;
    evidence.push("WordPress (wp-content / wp-includes)");
  }

  if (exposureEvidence) {
    const m = /PHP (\d+\.\d+\.\d+)/.exec(exposureEvidence);
    if (m) {
      detected = true;
      version = m[1];
      evidence.push(exposureEvidence);
    }
  }

  // WordPress REST API で PHP 利用を補強(バージョンは出ない)
  if (!detected) {
    const wpjson = await probe(origin + "/wp-json/");
    if (wpjson.status === 200 && /"namespaces"/.test(wpjson.snippet)) {
      detected = true;
      evidence.push("WordPress REST API (/wp-json/)");
    }
  }

  const assessment = assessPhpVersion(version, detected, evidence);

  const weight = 15;
  let status: CheckResult["status"];
  let score: number;
  let advice: string | undefined;
  switch (assessment.verdict) {
    case "not-php":
      status = "info"; score = weight; break;
    case "patched":
      status = "pass"; score = weight;
      advice = "CVE-2026-115560 対策として php.ini で session.upload_progress.enabled=0 を設定し、次回の定期リリースで更新してください。";
      break;
    case "unknown":
      status = "warn"; score = Math.round(weight / 2);
      advice = "ホスティング会社の対応状況を確認し、オーナーモードで php -v の結果を貼り付けて確定判定してください。";
      break;
    case "vulnerable":
      status = "fail"; score = 0;
      advice = "PHP を 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 以上へ直ちに更新してください。更新できない場合は WAF での遮断とホスティング会社への確認を行ってください。";
      break;
    case "eol":
      status = "fail"; score = 0;
      advice = "このブランチには修正版がありません。PHP 8.3 以上への移行計画を直ちに立て、移行までは WAF などで防御してください。";
      break;
  }

  const results: CheckResult[] = [
    {
      id: "php2shell",
      category: "PHP (2026年10月の重大脆弱性)",
      title: "PHP2Shell (CVE-2026-109618 / 109619) の影響",
      status,
      score,
      weight,
      detail: assessment.summary + (evidence.length ? ` 根拠: ${evidence.join(" / ")}` : ""),
      advice,
      evidence: version ? `PHP ${version}` : undefined,
    },
  ];

  if (assessment.detected) {
    results.push({
      id: "mod-php",
      category: "PHP (2026年10月の重大脆弱性)",
      title: "Apache mod_php 構成の推定",
      status: modPhp === true ? "warn" : modPhp === null ? "info" : "pass",
      score: modPhp === true ? 0 : 2,
      weight: 2,
      detail:
        modPhp === true
          ? `Server ヘッダーから Apache + mod_php と推定されます (${server})。公式はこの構成のリスクを特に高く評価しています。`
          : server
            ? `Server: ${server}。mod_php かどうかは外部から断定できません。`
            : "Server ヘッダーがないため判定できません。",
      advice: modPhp === true ? "PHP-FPM への移行を検討してください。" : undefined,
    });
  }

  return { assessment, results, modPhp };
}
