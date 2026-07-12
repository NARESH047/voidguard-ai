import { DatabaseProvider } from "@/components/Provider";
import "./globals.css";

export const metadata = {
  title: "VoidGuard AI | Autonomous Security Agency",
  description:
    "VoidGuard AI hunts leaked secrets, audits dependencies, and prepares secure GitHub remediations.",
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