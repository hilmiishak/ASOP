import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "ASOP | Autonomous Security Operations Platform",
  description:
    "AI-Enabled Security Assurance Platform — FastAPI, PostgreSQL, Next.js, Google Gemini AI",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
