import dns from "node:dns/promises";
import net from "node:net";

/** 内部ネットワークへのアクセスを防ぐ (SSRF 対策) */
/** ローカル検証専用。本番環境では絶対に設定しないこと */
export const ALLOW_PRIVATE = process.env.SCAN_ALLOW_PRIVATE === "1";

export async function assertPublicHost(hostname: string): Promise<void> {
  if (ALLOW_PRIVATE) return;
  if (/^(localhost|.*\.local|.*\.internal)$/i.test(hostname)) {
    throw new Error("内部ホストは診断できません");
  }
  const addrs = net.isIP(hostname)
    ? [hostname]
    : (await dns.lookup(hostname, { all: true }).catch(() => [])).map((a) => a.address);
  if (addrs.length === 0) throw new Error("ホスト名を解決できません");
  for (const a of addrs) {
    if (isPrivate(a)) throw new Error("プライベート IP アドレスは診断できません");
  }
}

function isPrivate(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  const l = ip.toLowerCase();
  if (l.startsWith("::ffff:")) return isPrivate(l.slice(7));
  return l === "::1" || l === "::" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80");
}
