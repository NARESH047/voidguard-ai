import { DatabaseProvider } from "@/components/Provider";
import "./globals.css";

export const metadata = {
  title: "Hermes Hack Speedrun",
  description: "Built for speed.",
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