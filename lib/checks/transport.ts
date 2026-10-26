import tls from "node:tls";
import type { CheckResult } from "../types";
import { fetchPage, type FetchedPage } from "../fetcher";

export async function checkHttps(
  page: FetchedPage,
  hostname: string,
  host: string = hostname
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const isHttps = page.finalUrl.startsWith("https://");

  results.push({
    id: "https",
    category: "通信の暗号化",
    title: "HTTPS で配信されている",
    status: isHttps ? "pass" : "fail",
    score: isHttps ? 10 : 0,
    weight: 10,
    detail: isHttps
      ? `最終 URL は HTTPS です: ${page.finalUrl}`
      : `最終 URL が HTTP のままです: ${page.finalUrl}`,
    advice: isHttps ? undefined : "TLS 証明書を導入し、全ページを HTTPS で配信してください。",
  });

  // HTTP → HTTPS リダイレクト
  const httpPage = await fetchPage(`http://${host}/`, { method: "HEAD" });
  const redirected =
    httpPage.error === undefined && httpPage.finalUrl.startsWith("https://");
  results.push({
    id: "http-redirect",
    category: "通信の暗号化",
    title: "HTTP から HTTPS へ自動リダイレクト",
    status: httpPage.error ? "unknown" : redirected ? "pass" : "fail",
    score: redirected ? 5 : 0,
    weight: 5,
    detail: httpPage.error
      ? `HTTP で接続できませんでした (${httpPage.error})。HTTP を閉じている場合は問題ありません。`
      : redirected
        ? `http://${host}/ → ${httpPage.finalUrl}`
        : `http://${host}/ は HTTPS にリダイレクトされません (status ${httpPage.status})`,
    advice: redirected ? undefined : "HTTP アクセスを 301 で HTTPS へ転送してください。",
  });

  // 証明書
  if (isHttps) {
    const cert = await getCertInfo(hostname);
    if (cert.error) {
      results.push({
        id: "tls-cert",
        category: "通信の暗号化",
        title: "TLS 証明書の有効性",
        status: "fail",
        score: 0,
        weight: 8,
        detail: `証明書の検証に失敗しました: ${cert.error}`,
        advice: "有効な証明書を設置し、中間証明書を含めて正しく配信してください。",
      });
    } else {
      const days = cert.daysLeft ?? 0;
      const status = days < 0 ? "fail" : days < 14 ? "warn" : "pass";
      results.push({
        id: "tls-cert",
        category: "通信の暗号化",
        title: "TLS 証明書の有効性",
        status,
        score: status === "pass" ? 8 : status === "warn" ? 4 : 0,
        weight: 8,
        detail: `発行者: ${cert.issuer} / 有効期限: ${cert.validTo} (残り ${days} 日) / プロトコル: ${cert.protocol}`,
        advice:
          status === "pass" ? undefined : "証明書の更新を行ってください。自動更新 (ACME) の導入を推奨します。",
      });
      const oldProto = cert.protocol === "TLSv1" || cert.protocol === "TLSv1.1";
      results.push({
        id: "tls-version",
        category: "通信の暗号化",
        title: "TLS 1.2 以上で接続できる",
        status: oldProto ? "fail" : "pass",
        score: oldProto ? 0 : 4,
        weight: 4,
        detail: `ネゴシエートされたプロトコル: ${cert.protocol}`,
        advice: oldProto ? "TLS 1.0/1.1 を無効化し、TLS 1.2 以上のみを許可してください。" : undefined,
      });
    }
  }
  return results;
}

function getCertInfo(hostname: string): Promise<{
  issuer?: string;
  validTo?: string;
  daysLeft?: number;
  protocol?: string;
  error?: string;
}> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() ?? "unknown";
        const authorized = socket.authorized;
        const authErr = socket.authorizationError;
        socket.end();
        if (!authorized) {
          resolve({ error: String(authErr ?? "unauthorized") });
          return;
        }
        const validTo = cert.valid_to;
        const daysLeft = Math.floor(
          (new Date(validTo).getTime() - Date.now()) / 86400000
        );
        const rawIssuer = cert.issuer?.O ?? cert.issuer?.CN ?? "不明";
        const issuer = Array.isArray(rawIssuer) ? rawIssuer.join(", ") : rawIssuer;
        resolve({ issuer, validTo, daysLeft, protocol });
      }
    );
    socket.on("error", (e) => resolve({ error: e.message }));
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ error: "timeout" });
    });
  });
}
