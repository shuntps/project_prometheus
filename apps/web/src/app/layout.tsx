import type { Metadata } from "next";
import type { ReactNode } from "react";

import { siteDescription, siteName } from "@/config/site";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: siteName,
  description: siteDescription,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a
          href="#main"
          className="sr-only rounded-pill focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-10 focus:bg-surface-highest focus:px-5 focus:py-3 focus:text-on-surface"
        >
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
