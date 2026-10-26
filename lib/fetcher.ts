export interface FetchedPage {
  url: string;
  finalUrl: string;
  status: number;
  headers: Headers;
  body: string;
  redirectChain: string[];
  error?: string;
}

const UA =
  "Mozilla/5.0 (compatible; SecurityScoreBot/0.1; +https://example.invalid/bot)";

/** リダイレクトを手動で追いながら取得し、経路を記録する */
export async function fetchPage(
  url: string,
  opts: { maxRedirects?: number; timeoutMs?: number; method?: "GET" | "HEAD" } = {}
): Promise<FetchedPage> {
  const { maxRedirects = 5, timeoutMs = 10000, method = "GET" } = opts;
  const chain: string[] = [];
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(current, {
        method,
        redirect: "manual",
        headers: { "user-agent": UA, accept: "text/html,*/*" },
        signal: controller.signal,
        cache: "no-store",
      });
      clearTimeout(timer);
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) {
        chain.push(current);
        current = new URL(loc, current).toString();
        continue;
      }
      let body = "";
      if (method === "GET") {
        const reader = res.body?.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        while (reader) {
          const { done, value } = await reader.read();
          if (done || !value) break;
          chunks.push(value);
          total += value.length;
          if (total > 512 * 1024) {
            reader.cancel().catch(() => {});
            break;
          }
        }
        body = new TextDecoder("utf-8", { fatal: false }).decode(
          concat(chunks)
        );
      }
      return {
        url,
        finalUrl: current,
        status: res.status,
        headers: res.headers,
        body,
        redirectChain: chain,
      };
    } catch (e) {
      clearTimeout(timer);
      return {
        url,
        finalUrl: current,
        status: 0,
        headers: new Headers(),
        body: "",
        redirectChain: chain,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }
  return {
    url,
    finalUrl: current,
    status: 0,
    headers: new Headers(),
    body: "",
    redirectChain: chain,
    error: "リダイレクトが多すぎます",
  };
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** 存在確認用。200 かつ HTML 以外、または特徴的な内容なら露出とみなす */
export async function probe(
  url: string,
  timeoutMs = 6000
): Promise<{ status: number; contentType: string; snippet: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": UA },
      signal: controller.signal,
      cache: "no-store",
    });
    clearTimeout(timer);
    const ct = res.headers.get("content-type") ?? "";
    const text = (await res.text()).slice(0, 400);
    return { status: res.status, contentType: ct, snippet: text };
  } catch {
    clearTimeout(timer);
    return { status: 0, contentType: "", snippet: "" };
  }
}
