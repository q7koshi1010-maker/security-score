"use client";
import type { CheckResult, PhpAssessment, ScanReport, Status } from "@/lib/types";

const LABEL: Record<Status, string> = { pass: "合格", warn: "注意", fail: "要対策", info: "情報", unknown: "不明" };

export function Badge({ status }: { status: Status }) {
  return <span className={`badge s-${status}`}>{LABEL[status]}</span>;
}

function Gauge({ score, grade }: { score: number; grade: string }) {
  const r = 64;
  const c = 2 * Math.PI * r;
  const color = score >= 75 ? "var(--pass)" : score >= 40 ? "var(--warn)" : "var(--fail)";
  return (
    <div className="gauge" role="img" aria-label={`スコア ${score} 点、評価 ${grade}`}>
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r={r} fill="none" stroke="var(--border)" strokeWidth="12" />
        <circle cx="75" cy="75" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} />
      </svg>
      <div className="num"><div><strong>{score}</strong><span>/ 100</span></div></div>
    </div>
  );
}

const VERDICT: Record<PhpAssessment["verdict"], { cls: string; title: string }> = {
  vulnerable: { cls: "s-fail", title: "PHP2Shell の影響を受けるバージョンです" },
  eol: { cls: "s-fail", title: "修正版のないサポート終了バージョンです" },
  unknown: { cls: "s-warn", title: "PHP を使用中ですがバージョンは要確認です" },
  patched: { cls: "s-pass", title: "PHP2Shell は修正済みのバージョンです" },
  "not-php": { cls: "s-info", title: "PHP の利用は検出されませんでした" },
};

export function PhpPanel({ php }: { php: PhpAssessment }) {
  const v = VERDICT[php.verdict];
  return (
    <div className={`php-banner ${v.cls}`}>
      <h3>PHP 診断: {v.title}{php.version ? ` (PHP ${php.version})` : ""}</h3>
      <p style={{ color: "var(--text)" }}>{php.summary}</p>
      {php.evidence.length > 0 && (
        <p className="meta" style={{ marginTop: 6 }}>検出根拠: {php.evidence.join(" / ")}</p>
      )}
      {php.advisories.length > 0 && (
        <table className="adv">
          <thead><tr><th>脆弱性</th><th>深刻度</th><th>判定</th><th>対応</th></tr></thead>
          <tbody>
            {php.advisories.map((a) => (
              <tr key={a.id}>
                <td><strong>{a.id}</strong><br /><span className="meta">{a.title}</span></td>
                <td>{a.severity}</td>
                <td><Badge status={a.affected === null ? "unknown" : a.affected ? "fail" : "pass"} /></td>
                <td>{a.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Item({ r }: { r: CheckResult }) {
  return (
    <details className="item" open={r.status === "fail"}>
      <summary>
        <Badge status={r.status} />
        <span className="t">{r.title}</span>
        <span className="pts">{r.status === "unknown" ? "対象外" : `${r.score} / ${r.weight}`}</span>
      </summary>
      <div className="body">
        <p>{r.detail}</p>
        {r.advice && <div className="advice"><strong>対策:</strong> {r.advice}</div>}
      </div>
    </details>
  );
}

export function Report({ report }: { report: ScanReport }) {
  const cats = Array.from(new Set(report.results.map((r) => r.category)));
  const count = (s: Status) => report.results.filter((r) => r.status === s).length;
  const gradeCls = report.totalScore >= 75 ? "s-pass" : report.totalScore >= 40 ? "s-warn" : "s-fail";
  return (
    <section>
      <div className="card summary">
        <Gauge score={report.totalScore} grade={report.grade} />
        <div>
          <span className={`grade ${gradeCls}`}>評価 {report.grade}</span>
          <div className="meta">{report.finalUrl}</div>
          <div className="meta">診断日時: {new Date(report.scannedAt).toLocaleString("ja-JP")} ({(report.durationMs / 1000).toFixed(1)} 秒)</div>
          <div className="counts">
            <span><Badge status="fail" /> {count("fail")}</span>
            <span><Badge status="warn" /> {count("warn")}</span>
            <span><Badge status="pass" /> {count("pass")}</span>
          </div>
        </div>
      </div>
      <PhpPanel php={report.php} />
      <h2>診断項目</h2>
      {cats.map((c) => (
        <div className="cat" key={c}>
          <h3>{c}</h3>
          {report.results.filter((r) => r.category === c).map((r) => <Item key={r.id} r={r} />)}
        </div>
      ))}
    </section>
  );
}
