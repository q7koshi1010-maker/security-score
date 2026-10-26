import type { CheckResult } from "../types";
import { probe } from "../fetcher";

interface Target {
  path: string;
  label: string;
  /** 本文がこのパターンに一致した場合のみ露出とみなす (誤検知防止) */
  pattern: RegExp;
  weight: number;
}

const TARGETS: Target[] = [
  { path: "/.git/HEAD", label: "Git リポジトリ (.git/HEAD)", pattern: /^ref:\s*refs\//, weight: 6 },
  { path: "/.env", label: "環境変数ファイル (.env)", pattern: /^[A-Z_]{3,}=.+/m, weight: 6 },
  { path: "/phpinfo.php", label: "phpinfo.php", pattern: /PHP Version|phpinfo\(\)/i, weight: 4 },
  { path: "/info.php", label: "info.php (phpinfo)", pattern: /PHP Version|phpinfo\(\)/i, weight: 4 },
  { path: "/wp-config.php.bak", label: "wp-config.php のバックアップ", pattern: /DB_PASSWORD|DB_NAME/, weight: 6 },
  { path: "/.DS_Store", label: ".DS_Store", pattern: /^\x00\x00\x00\x01Bud1/, weight: 1 },
  { path: "/composer.json", label: "composer.json (依存情報の露出)", pattern: /"require"\s*:/, weight: 2 },
];

export async function checkExposure(origin: string): Promise<CheckResult[]> {
  const found: { label: string; path: string; weight: number }[] = [];
  const phpinfoVersion: string[] = [];
  await Promise.all(
    TARGETS.map(async (t) => {
      const res = await probe(origin + t.path);
      if (res.status === 200 && t.pattern.test(res.snippet)) {
        found.push({ label: t.label, path: t.path, weight: t.weight });
        const m = /PHP Version\s*(?:<[^>]*>)*\s*(\d+\.\d+\.\d+)/i.exec(res.snippet);
        if (m) phpinfoVersion.push(m[1]);
      }
    })
  );
  const weight = 10;
  const penalty = Math.min(weight, found.reduce((n, f) => n + f.weight, 0));
  const result: CheckResult = {
    id: "exposure",
    category: "機密ファイルの露出",
    title: "公開されてはいけないファイル",
    status: found.length === 0 ? "pass" : penalty >= 6 ? "fail" : "warn",
    score: weight - penalty,
    weight,
    detail:
      found.length === 0
        ? `${TARGETS.length} 件の代表的なパスを確認し、露出は見つかりませんでした。`
        : `露出: ${found.map((f) => `${f.label} (${f.path})`).join(", ")}`,
    advice:
      found.length === 0
        ? undefined
        : "該当ファイルを公開ディレクトリから削除するか、Web サーバーの設定でアクセスを拒否してください。.git や .env の露出は認証情報漏えいに直結します。",
    evidence: phpinfoVersion.length ? `phpinfo から PHP ${phpinfoVersion[0]} を検出` : undefined,
  };
  return [result];
}
