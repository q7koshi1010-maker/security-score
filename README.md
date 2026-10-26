# セキュリティスコア診断 (プロトタイプ)

URL を入力すると、Web サイトのセキュリティ設定を 100 点満点で採点する Next.js アプリです。
2026年10月の PHP 重大脆弱性 (PHP2Shell: CVE-2026-109618 / CVE-2026-109619) と関連する CVE-2026-115560 の影響も判定します。

## 起動

```bash
npm install
npm run dev        # http://localhost:3000
```

Vercel にそのままデプロイできます (API は Node.js ランタイムで動作)。

## 診断項目

| カテゴリ | 内容 |
| --- | --- |
| PHP | PHP 利用の検出 (X-Powered-By / PHPSESSID / .php URL / WordPress / phpinfo 露出)、バージョン判定、Apache mod_php の推定 |
| 通信の暗号化 | HTTPS、HTTP→HTTPS リダイレクト、証明書の有効期限、TLS バージョン |
| セキュリティヘッダー | HSTS、CSP、X-Frame-Options / frame-ancestors、X-Content-Type-Options、Referrer-Policy、Permissions-Policy、Server / X-Powered-By の情報漏えい |
| Cookie | Secure / HttpOnly / SameSite |
| 機密ファイルの露出 | .git、.env、phpinfo、wp-config バックアップ、composer.json など |
| コンテンツ | 混在コンテンツ |
| DNS / メール | SPF、DMARC、CAA |

PHP が修正版未満、またはサポート終了ブランチの場合、総合スコアは 39 点 (評価 F) を上限にします。

## オーナーモード

外部からは PHP のバージョンが分からないことが多いため、サイト所有者が `php -v` または phpinfo() の出力を貼り付けると確定判定します。外部通信は行いません。

## 脆弱性データの更新

`lib/php-advisories.ts` に項目を追加するだけで判定に反映されます。`fixedIn` に修正版、`SUPPORTED_BRANCHES` にサポート中のブランチを記載します。

## 安全設計

- 受動的なチェックのみ。攻撃的な通信は送りません。
- SSRF 対策として、プライベート IP・localhost・非標準ポートへの診断を拒否します (`lib/ssrf.ts`)。
- 簡易レート制限 (1 IP あたり 10 回/分)。本番では Upstash などの外部ストアに置き換えてください。
- 環境変数 `SCAN_ALLOW_PRIVATE=1` はローカル検証用です。本番では設定しないでください。
