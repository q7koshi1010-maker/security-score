import dns from "node:dns/promises";
import net from "node:net";
import type { CheckResult } from "../types";

const CAT = "DNS / メール";

export async function checkDns(hostname: string): Promise<CheckResult[]> {
  if (net.isIP(hostname)) {
    return [{ id: "dns", category: CAT, title: "SPF / DMARC / CAA", status: "unknown", score: 0, weight: 8, detail: "IP アドレス指定のため DNS 系の診断は対象外です。" }];
  }
  const root = registrableDomain(hostname);
  const r: CheckResult[] = [];

  const spf = await txt(root).then((t) => t.find((v) => /^v=spf1/i.test(v)) ?? null);
  r.push({
    id: "spf",
    category: CAT,
    title: "SPF レコード",
    status: spf ? (/\+all/.test(spf) ? "warn" : "pass") : "fail",
    score: spf ? (/\+all/.test(spf) ? 1 : 3) : 0,
    weight: 3,
    detail: spf ? `${root}: ${spf}` : `${root} に SPF (v=spf1) がありません。`,
    advice: spf ? (/\+all/.test(spf) ? "+all はなりすましを許可します。~all または -all にしてください。" : undefined) : "送信元サーバーを列挙した SPF レコードを設定してください。メールを送らないドメインは v=spf1 -all を設定します。",
    evidence: spf ?? undefined,
  });

  const dmarc = await txt(`_dmarc.${root}`).then((t) => t.find((v) => /^v=DMARC1/i.test(v)) ?? null);
  const policy = dmarc ? /p=(none|quarantine|reject)/i.exec(dmarc)?.[1]?.toLowerCase() : undefined;
  r.push({
    id: "dmarc",
    category: CAT,
    title: "DMARC レコード",
    status: !dmarc ? "fail" : policy === "none" ? "warn" : "pass",
    score: !dmarc ? 0 : policy === "none" ? 1 : 3,
    weight: 3,
    detail: dmarc ? `_dmarc.${root}: ${dmarc}` : `_dmarc.${root} がありません。`,
    advice: !dmarc ? "v=DMARC1; p=quarantine; rua=mailto:... を設定してください。" : policy === "none" ? "p=none は監視のみです。p=quarantine または p=reject へ強化してください。" : undefined,
    evidence: dmarc ?? undefined,
  });

  const caa = await dns.resolveCaa(root).catch(() => []);
  r.push({
    id: "caa",
    category: CAT,
    title: "CAA レコード (証明書発行の制限)",
    status: caa.length ? "pass" : "info",
    score: caa.length ? 2 : 1,
    weight: 2,
    detail: caa.length ? caa.map((c) => `${c.issue ?? c.issuewild ?? ""}`).filter(Boolean).join(", ") : "CAA レコードはありません (任意)。",
    advice: caa.length ? undefined : "利用する認証局のみを許可する CAA レコードの設定を推奨します。",
  });

  return r;
}

async function txt(name: string): Promise<string[]> {
  try {
    const recs = await dns.resolveTxt(name);
    return recs.map((parts) => parts.join(""));
  } catch {
    return [];
  }
}

function registrableDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const sld = parts[parts.length - 2];
  // co.jp, ne.jp, com.au など 2 段 TLD の簡易対応
  if (/^(co|ne|or|ac|go|ed|gr|lg|com|net|org)$/.test(sld) && parts[parts.length - 1].length === 2) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}
