import type { Metadata } from "next";
import "@/index.css";

export const metadata: Metadata = {
  title: "SafeCheck",
  description:
    "File integrity and security scanner for executables downloaded from untrusted sources.",
  icons: {
    icon: [{ url: "/shield.jpg", type: "image/jpeg" }],
    shortcut: [{ url: "/shield.jpg", type: "image/jpeg" }],
    apple: [{ url: "/shield.jpg", type: "image/jpeg" }],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
