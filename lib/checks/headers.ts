import type { CheckResult } from "../types";

const CAT = "セキュリティヘッダー";

export function checkHeaders(h: Headers, isHttps: boolean): CheckResult[] {
  const r: CheckResult[] = [];

  const hsts = h.get("strict-transport-security");
  if (!isHttps) {
    r.push(mk("hsts", "HSTS (Strict-Transport-Security)", "fail", 0, 8, "HTTPS でないため HSTS は無効です。"));
  } else if (!hsts) {
    r.push(mk("hsts", "HSTS (Strict-Transport-Security)", "fail", 0, 8, "ヘッダーがありません。", "Strict-Transport-Security: max-age=31536000; includeSubDomains を設定してください。"));
  } else {
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    const ok = maxAge >= 15552000;
    r.push(mk("hsts", "HSTS (Strict-Transport-Security)", ok ? "pass" : "warn", ok ? 8 : 4, 8, `値: ${hsts}`, ok ? undefined : "max-age を 180 日 (15552000 秒) 以上にしてください。", hsts));
  }

  const csp = h.get("content-security-policy");
  if (!csp) {
    r.push(mk("csp", "Content-Security-Policy", "fail", 0, 8, "ヘッダーがありません。XSS の影響を軽減できません。", "まずは Content-Security-Policy-Report-Only で導入し、段階的に強化してください。"));
  } else {
    const weak = /unsafe-inline|unsafe-eval|\*\s*;/.test(csp) || !/default-src|script-src/.test(csp);
    r.push(mk("csp", "Content-Security-Policy", weak ? "warn" : "pass", weak ? 4 : 8, 8, weak ? "設定されていますが unsafe-inline / unsafe-eval / ワイルドカードを含むか、script-src が未定義です。" : "設定されています。", weak ? "unsafe-* を排除し nonce / hash ベースへ移行してください。" : undefined, csp.slice(0, 300)));
  }

  const xfo = h.get("x-frame-options");
  const cspFrame = csp ? /frame-ancestors/i.test(csp) : false;
  if (xfo || cspFrame) {
    r.push(mk("xfo", "クリックジャッキング対策 (X-Frame-Options / frame-ancestors)", "pass", 5, 5, xfo ? `X-Frame-Options: ${xfo}` : "CSP の frame-ancestors で制御されています。"));
  } else {
    r.push(mk("xfo", "クリックジャッキング対策 (X-Frame-Options / frame-ancestors)", "fail", 0, 5, "どちらも設定されていません。", "X-Frame-Options: DENY または CSP の frame-ancestors 'none' を設定してください。"));
  }

  const xcto = h.get("x-content-type-options");
  const okXcto = xcto?.toLowerCase().includes("nosniff") ?? false;
  r.push(mk("xcto", "X-Content-Type-Options: nosniff", okXcto ? "pass" : "fail", okXcto ? 3 : 0, 3, okXcto ? "設定されています。" : "設定されていません。", okXcto ? undefined : "X-Content-Type-Options: nosniff を追加してください。"));

  const rp = h.get("referrer-policy");
  const okRp = !!rp && !/unsafe-url|no-referrer-when-downgrade/i.test(rp);
  r.push(mk("referrer", "Referrer-Policy", rp ? (okRp ? "pass" : "warn") : "fail", okRp ? 3 : rp ? 1 : 0, 3, rp ? `値: ${rp}` : "設定されていません。", okRp ? undefined : "Referrer-Policy: strict-origin-when-cross-origin を推奨します。"));

  const pp = h.get("permissions-policy");
  r.push(mk("permissions", "Permissions-Policy", pp ? "pass" : "warn", pp ? 2 : 0, 2, pp ? `値: ${pp.slice(0, 200)}` : "設定されていません。", pp ? undefined : "camera=(), microphone=(), geolocation=() など不要な機能を無効化してください。"));

  // 情報漏えい
  const server = h.get("server");
  const xpb = h.get("x-powered-by");
  const leaks: string[] = [];
  if (server && /\d+\.\d+/.test(server)) leaks.push(`Server: ${server}`);
  if (xpb) leaks.push(`X-Powered-By: ${xpb}`);
  r.push(mk("leak", "サーバー情報の非公開 (Server / X-Powered-By)", leaks.length ? "warn" : "pass", leaks.length ? 0 : 4, 4, leaks.length ? `バージョン情報が露出しています: ${leaks.join(" / ")}` : "バージョン情報は露出していません。", leaks.length ? "X-Powered-By を削除 (expose_php=Off) し、Server ヘッダーからバージョン番号を除去してください。" : undefined));

  return r;
}

function mk(id: string, title: string, status: CheckResult["status"], score: number, weight: number, detail: string, advice?: string, evidence?: string): CheckResult {
  return { id, category: CAT, title, status, score, weight, detail, advice, evidence };
}
