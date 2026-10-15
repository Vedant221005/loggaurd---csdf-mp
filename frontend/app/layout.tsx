import "./globals.css";
import { Layout } from "../components/layout/Layout";
export const metadata = { title: "LogGuard | System Log Forensic Analyzer", description: "Local digital forensics triage for system logs" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body><Layout>{children}</Layout></body></html>; }
