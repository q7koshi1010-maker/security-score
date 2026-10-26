import type { CheckResult } from "../types";

export function checkMixedContent(body: string, isHttps: boolean): CheckResult[] {
  if (!isHttps) {
    return [{ id: "mixed", category: "コンテンツ", title: "混在コンテンツ (HTTPS 内の HTTP 読み込み)", status: "unknown", score: 0, weight: 4, detail: "HTTPS でないため評価対象外です。" }];
  }
  const re = /<(?:script|link|img|iframe|video|audio|source)[^>]+(?:src|href)=["']http:\/\/[^"']+["']/gi;
  const hits = body.match(re) ?? [];
  const urls = hits.map((h) => /http:\/\/[^"']+/.exec(h)?.[0] ?? "").filter(Boolean).slice(0, 5);
  return [
    {
      id: "mixed",
      category: "コンテンツ",
      title: "混在コンテンツ (HTTPS 内の HTTP 読み込み)",
      status: hits.length ? "fail" : "pass",
      score: hits.length ? 0 : 4,
      weight: 4,
      detail: hits.length ? `${hits.length} 件の HTTP 読み込みがあります: ${urls.join(", ")}` : "HTTP でのリソース読み込みはありません。",
      advice: hits.length ? "すべてのリソースを HTTPS で読み込むか、CSP の upgrade-insecure-requests を利用してください。" : undefined,
    },
  ];
}
