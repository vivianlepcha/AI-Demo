import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "My Pandora | Login & Join",
  description: "Sign in or join My Pandora to earn points, get personal offers and enjoy exclusive benefits.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
