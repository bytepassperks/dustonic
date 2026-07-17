import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  HardDrive,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";

type ScanCategory = {
  name: string;
  items: number;
  size: string;
};

const initialCategories: ScanCategory[] = [
  { name: "System cache", items: 0, size: "Ready" },
  { name: "Browser traces", items: 0, size: "Ready" },
  { name: "Temporary files", items: 0, size: "Ready" },
];

export default function App() {
  const [categories, setCategories] = useState(initialCategories);
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState("Not scanned yet");

  async function handleScan() {
    setScanning(true);
    try {
      const result = await invoke<ScanCategory[]>("scan_system");
      setCategories(result);
      setLastScan("Just now");
    } finally {
      setScanning(false);
    }
  }

  return (
    <main className="min-h-screen overflow-hidden bg-ink text-slate-100">
      <div className="pointer-events-none absolute -left-40 -top-40 h-96 w-96 rounded-full bg-teal/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-40 top-1/3 h-[32rem] w-[32rem] rounded-full bg-blue/10 blur-3xl" />
      <div className="relative mx-auto flex min-h-screen max-w-6xl flex-col px-6 py-7 lg:px-10">
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/logo.png" alt="Dustonic" className="h-10 w-10 rounded-xl shadow-glow" />
            <div>
              <p className="text-lg font-semibold tracking-tight">Dustonic</p>
              <p className="text-xs text-slate-500">PC care, made simple</p>
            </div>
          </div>
          <div className="hidden items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-slate-400 sm:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-teal shadow-[0_0_10px_#12B5A5]" />
            Protected
          </div>
        </header>

        <section className="flex flex-1 flex-col justify-center py-16">
          <div className="max-w-2xl">
            <p className="mb-5 flex items-center gap-2 text-sm font-medium text-teal">
              <ShieldCheck size={17} /> Your cleaner is ready
            </p>
            <h1 className="max-w-xl text-5xl font-semibold leading-[1.08] tracking-[-0.04em] sm:text-6xl">
              A faster, cleaner PC starts here.
            </h1>
            <p className="mt-6 max-w-lg text-base leading-7 text-slate-400">
              Find digital clutter, reclaim space, and keep your system feeling fresh with a focused
              scan.
            </p>
            <button
              type="button"
              onClick={handleScan}
              disabled={scanning}
              className="mt-9 inline-flex items-center gap-3 rounded-xl bg-gradient-to-r from-teal to-blue px-6 py-3.5 text-sm font-semibold text-white shadow-lg shadow-teal/10 transition hover:brightness-110 disabled:cursor-wait disabled:opacity-70"
            >
              <ScanSearch size={18} />
              {scanning ? "Scanning…" : "Scan my PC"}
              {!scanning && <ArrowUpRight size={17} />}
            </button>
          </div>

          <div className="mt-20 grid gap-4 md:grid-cols-3">
            {categories.map((category) => (
              <article
                key={category.name}
                className="rounded-2xl border border-white/[0.08] bg-panel/80 p-5 backdrop-blur"
              >
                <div className="mb-8 flex items-center justify-between">
                  <div className="rounded-lg bg-white/[0.06] p-2.5 text-teal">
                    {category.name === "System cache" ? (
                      <HardDrive size={18} />
                    ) : category.name === "Browser traces" ? (
                      <Activity size={18} />
                    ) : (
                      <CheckCircle2 size={18} />
                    )}
                  </div>
                  <span className="text-xs text-slate-500">{category.size}</span>
                </div>
                <h2 className="text-sm font-medium text-slate-200">{category.name}</h2>
                <p className="mt-1 text-xs text-slate-500">
                  {category.items ? `${category.items} items found` : "Waiting for your first scan"}
                </p>
              </article>
            ))}
          </div>
          <p className="mt-5 text-xs text-slate-600">Last scan: {lastScan}</p>
        </section>

        <footer className="flex flex-col gap-2 border-t border-white/[0.07] pt-5 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <span>Dustonic 0.1.0 · Built for a cleaner tomorrow</span>
          <span>Lightweight. Private. Yours.</span>
        </footer>
      </div>
    </main>
  );
}
