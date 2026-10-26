import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "セキュリティスコア診断",
  description: "URL を入力するだけで Web サイトのセキュリティ設定と PHP の重大脆弱性 (PHP2Shell) の影響を診断します。",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
