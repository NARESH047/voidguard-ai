import { DatabaseProvider } from "@/components/Provider";
import "./globals.css";

export const metadata = {
  title: "VoidGuard AI | Autonomous Security Agency",
  description:
    "Open, no-login security audits for public GitHub repositories with redacted evidence and source-bound advisory grounding.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-slate-950 text-slate-50">
        <DatabaseProvider>
          {children}
        </DatabaseProvider>
      </body>
    </html>
  );
}