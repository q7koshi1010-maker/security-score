"use client";
import { useState } from "react";
import type { PhpAssessment, ScanReport } from "@/lib/types";
import { PhpPanel, Report } from "@/components/Report";

type Tab = "scan" | "owner";

export default function Home() {
  const [tab, setTab] = useState<Tab>("scan");
  return (
    <main>
      <h1>セキュリティスコア診断</h1>
      <p className="lead">
        URL を入力するだけで、Web サイトのセキュリティ設定を 100 点満点で採点します。
        2026年10月に公表された PHP の重大脆弱性 (PHP2Shell) の影響も判定します。
      </p>
      <div className="tabs" role="tablist">
        <button className="tab" role="tab" aria-selected={tab === "scan"} onClick={() => setTab("scan")}>URL で診断</button>
        <button className="tab" role="tab" aria-selected={tab === "owner"} onClick={() => setTab("owner")}>オーナーモード (PHP 確定判定)</button>
      </div>
      {tab === "scan" ? <ScanTab /> : <OwnerTab />}
      <p className="note">
        本ツールは公開情報を読み取る受動的な診断のみを行い、攻撃的な通信は送りません。結果は設定の健全性の目安であり、脆弱性診断 (ペネトレーションテスト) の代替ではありません。
        PHP の脆弱性情報は 2026年10月25日時点のものです。
      </p>
    </main>
  );
}

function ScanTab() {
  const [url, setUrl] = useState("");
  const [agree, setAgree] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "診断に失敗しました");
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <form className="scan" onSubmit={onSubmit}>
          <input type="text" inputMode="url" placeholder="例: example.com" value={url}
            onChange={(e) => setUrl(e.target.value)} aria-label="診断する URL" required />
          <button className="primary" disabled={loading || !agree || !url.trim()}>
            {loading ? <><span className="spinner" />診断中…</> : "診断する"}
          </button>
        </form>
        <label className="consent">
          <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} />
          <span>自分が管理する、または診断の許可を得たサイトであることを確認しました。</span>
        </label>
        {error && <div className="error">{error}</div>}
      </div>
      {report && <Report report={report} />}
    </>
  );
}

function OwnerTab() {
  const [text, setText] = useState("");
  const [progress, setProgress] = useState("unknown");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PhpAssessment | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/php-check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, uploadProgress: progress }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "判定に失敗しました");
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <p style={{ marginTop: 0 }}>
          サーバーで <code>php -v</code> を実行した結果、または phpinfo() の出力を貼り付けてください。
          外部からは分からない正確なバージョンで、PHP2Shell と関連脆弱性の影響を確定判定します。
          入力内容は判定にのみ使い、保存しません。
        </p>
        <form onSubmit={onSubmit}>
          <textarea value={text} onChange={(e) => setText(e.target.value)}
            placeholder={"PHP 8.3.30 (cli) (built: Sep 30 2026 10:12:44) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.30"} aria-label="php -v の出力" />
          <div className="row">
            <label htmlFor="prog">session.upload_progress.enabled:</label>
            <select id="prog" value={progress} onChange={(e) => setProgress(e.target.value)} style={{ flex: "0 0 auto" }}>
              <option value="unknown">わからない</option>
              <option value="on">On (1)</option>
              <option value="off">Off (0)</option>
            </select>
            <button className="primary" disabled={loading || !text.trim()}>
              {loading ? <><span className="spinner" />判定中…</> : "判定する"}
            </button>
          </div>
        </form>
        {error && <div className="error">{error}</div>}
      </div>
      {result && <PhpPanel php={result} />}
    </>
  );
}
