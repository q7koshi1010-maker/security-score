import type { CheckResult } from "../types";

export function checkCookies(h: Headers, isHttps: boolean): CheckResult[] {
  const raw = h.getSetCookie ? h.getSetCookie() : [];
  if (raw.length === 0) {
    return [
      {
        id: "cookies",
        category: "Cookie",
        title: "Cookie 属性 (Secure / HttpOnly / SameSite)",
        status: "info",
        score: 5,
        weight: 5,
        detail: "トップページでは Cookie が発行されていません。",
      },
    ];
  }
  const problems: string[] = [];
  for (const c of raw) {
    const name = c.split("=")[0].trim();
    const lower = c.toLowerCase();
    const miss: string[] = [];
    if (isHttps && !/;\s*secure/.test(lower)) miss.push("Secure");
    if (!/;\s*httponly/.test(lower)) miss.push("HttpOnly");
    if (!/;\s*samesite=/.test(lower)) miss.push("SameSite");
    if (miss.length) problems.push(`${name}: ${miss.join(", ")} なし`);
  }
  const ok = problems.length === 0;
  return [
    {
      id: "cookies",
      category: "Cookie",
      title: "Cookie 属性 (Secure / HttpOnly / SameSite)",
      status: ok ? "pass" : "warn",
      score: ok ? 5 : 2,
      weight: 5,
      detail: ok ? `${raw.length} 件の Cookie はすべて適切な属性を持っています。` : problems.join(" / "),
      advice: ok ? undefined : "セッション Cookie には Secure; HttpOnly; SameSite=Lax (または Strict) を付与してください。",
    },
  ];
}
