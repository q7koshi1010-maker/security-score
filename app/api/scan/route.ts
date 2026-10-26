import { NextResponse } from "next/server";
import { scan } from "@/lib/scanner";

export const runtime = "nodejs";
export const maxDuration = 60;

// 簡易レート制限 (インスタンス単位)。本番では Upstash などの外部ストアを推奨
const hits = new Map<string, number[]>();
function limited(ip: string): boolean {
  const now = Date.now();
  const arr = (hits.get(ip) ?? []).filter((t) => now - t < 60_000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > 10;
}

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
  if (limited(ip)) {
    return NextResponse.json({ error: "リクエストが多すぎます。1 分後に再試行してください。" }, { status: 429 });
  }
  let url: unknown;
  try {
    ({ url } = await req.json());
  } catch {
    return NextResponse.json({ error: "不正なリクエストです" }, { status: 400 });
  }
  if (typeof url !== "string" || url.length > 2048 || !url.trim()) {
    return NextResponse.json({ error: "URL を入力してください" }, { status: 400 });
  }
  try {
    const report = await scan(url);
    return NextResponse.json(report);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "診断に失敗しました" }, { status: 422 });
  }
}
