import {
  PHP_ADVISORIES,
  SUPPORTED_BRANCHES,
  branchOf,
  compareVersion,
} from "./php-advisories";
import type { AdvisoryMatch, PhpAssessment } from "./types";

/** バージョン文字列から PHP の脆弱性有無を判定する(外部診断・オーナーモード共通) */
export function assessPhpVersion(
  version: string | null,
  detected: boolean,
  evidence: string[]
): PhpAssessment {
  if (!detected) {
    return {
      detected: false,
      version: null,
      evidence,
      verdict: "not-php",
      summary: "PHP の利用は検出されませんでした。",
      advisories: [],
    };
  }

  if (!version) {
    return {
      detected: true,
      version: null,
      evidence,
      verdict: "unknown",
      summary:
        "PHP の利用を検出しましたが、バージョンは外部から特定できませんでした。オーナーモードで php -v の出力を貼り付けると確定判定できます。",
      advisories: PHP_ADVISORIES.map((a) => ({
        id: a.id,
        title: a.title,
        severity: a.severity,
        affected: null,
        note: "バージョン不明のため要確認",
      })),
    };
  }

  const branch = branchOf(version);
  const supported = branch !== null && SUPPORTED_BRANCHES.includes(branch);
  const advisories: AdvisoryMatch[] = PHP_ADVISORIES.map((a) => {
    const fixed = branch ? a.fixedIn[branch] : undefined;
    const noFixAnywhere = Object.keys(a.fixedIn).length === 0;
    let affected: boolean | null;
    let note: string;
    if (noFixAnywhere) {
      affected = true;
      note = a.mitigation ?? "修正版は未公開です。";
    } else if (!fixed) {
      affected = true;
      note = `${branch} 系には修正版がありません。サポート中のブランチ(${SUPPORTED_BRANCHES.join(", ")})へ移行してください。`;
    } else if (compareVersion(version, fixed) < 0) {
      affected = true;
      note = `${fixed} 以上へ更新してください。`;
    } else {
      affected = false;
      note = `${fixed} 以上のため修正済みです。`;
    }
    return { id: a.id, title: a.title, severity: a.severity, affected, note };
  });

  const criticalHit = advisories.some(
    (m) => m.affected && m.severity === "緊急"
  );

  let verdict: PhpAssessment["verdict"];
  let summary: string;
  if (!supported) {
    verdict = "eol";
    summary = `PHP ${version} はセキュリティ修正が提供されないブランチです。PHP2Shell (CVE-2026-109618/109619) の修正版が存在しないため、サポート中のバージョンへの移行が必要です。`;
  } else if (criticalHit) {
    verdict = "vulnerable";
    summary = `PHP ${version} は PHP2Shell (CVE-2026-109618/109619) の影響を受けます。直ちに修正版へ更新してください。`;
  } else {
    verdict = "patched";
    summary = `PHP ${version} は PHP2Shell の修正版以上です。未修正の CVE-2026-115560 については暫定設定を確認してください。`;
  }

  return { detected: true, version, evidence, verdict, summary, advisories };
}

/** `php -v` や phpinfo の出力からバージョンを抽出する */
export function extractPhpVersionFromText(text: string): string | null {
  const m =
    text.match(/PHP\s+(\d+\.\d+\.\d+)/i) ??
    text.match(/PHP Version\s*(?:<[^>]*>)?\s*(\d+\.\d+\.\d+)/i) ??
    text.match(/\b(\d+\.\d+\.\d+)\b/);
  return m ? m[1] : null;
}
