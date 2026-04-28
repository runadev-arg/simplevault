import type { JSX } from "react";

export default function HomePage(): JSX.Element {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="max-w-md text-center space-y-4">
        <h1 className="text-4xl font-semibold tracking-tight">SimpleVault</h1>
        <p className="text-zinc-400">Coming soon — your secure, self-hosted vault.</p>
      </div>
    </main>
  );
}
