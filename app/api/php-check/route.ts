import { NextResponse } from "next/server";
import { assessPhpVersion, extractPhpVersionFromText } from "@/lib/php";

export const runtime = "nodejs";

/** オーナーモード: php -v や phpinfo の出力から確定判定する。外部通信はしない */
export async function POST(req: Request) {
  let text: unknown;
  let uploadProgress: unknown;
  try {
    ({ text, uploadProgress } = await req.json());
  } catch {
    return NextResponse.json({ error: "不正なリクエストです" }, { status: 400 });
  }
  if (typeof text !== "string" || !text.trim() || text.length > 200_000) {
    return NextResponse.json({ error: "php -v の出力を貼り付けてください" }, { status: 400 });
  }
  const version = extractPhpVersionFromText(text);
  if (!version) {
    return NextResponse.json({ error: "PHP のバージョンを読み取れませんでした" }, { status: 422 });
  }
  const assessment = assessPhpVersion(version, true, ["オーナーによる入力"]);

  // phpinfo を貼られた場合は session.upload_progress.enabled も読み取る
  let progress: "on" | "off" | "unknown" = "unknown";
  const m = /session\.upload_progress\.enabled\s*(?:<[^>]*>\s*)*(On|Off|1|0)/i.exec(text);
  if (m) progress = /on|1/i.test(m[1]) ? "on" : "off";
  else if (uploadProgress === "on" || uploadProgress === "off") progress = uploadProgress;

  assessment.advisories = assessment.advisories.map((a) =>
    a.id === "CVE-2026-115560"
      ? {
          ...a,
          affected: progress === "off" ? false : progress === "on" ? true : null,
          note:
            progress === "off"
              ? "session.upload_progress.enabled=0 のため暫定対策済みです。"
              : progress === "on"
                ? "session.upload_progress.enabled が有効です。0 に設定してください。"
                : "session.upload_progress.enabled の値を確認してください (php -i | grep upload_progress)。",
        }
      : a
  );
  return NextResponse.json(assessment);
}
