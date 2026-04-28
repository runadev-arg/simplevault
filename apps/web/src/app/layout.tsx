import type { Metadata, Viewport } from "next";
import type { JSX, ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  title: "SimpleVault",
  description: "Your secure, self-hosted password and notes vault.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#0a0a0a",
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
};

export default function RootLayout({ children }: { children: ReactNode }): JSX.Element {
  return (
    <html lang="es" className="dark" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
