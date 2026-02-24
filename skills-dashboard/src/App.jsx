import { useState } from "react";
import { useSkillsData } from "./hooks/useSkillsData";
import { Header } from "./components/Header";
import { OverviewSection } from "./sections/OverviewSection";
import { SecuritySection } from "./sections/SecuritySection";
import { AuthorsSection } from "./sections/AuthorsSection";
import { BrowseSection } from "./sections/BrowseSection";

function LoadingScreen({ progress }) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center gap-6">
      <div className="border border-dashed border-[#393939] p-8 max-w-sm w-full text-center">
        <div className="w-8 h-8 border-2 border-[#393939] border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <div className="text-sm font-semibold mb-1">Loading Skills Catalog</div>
        <div className="text-[11px] text-[#6b6b6b]">{progress}</div>
      </div>
      <div className="text-[10px] text-[#9e9e9e]">Powered by DuckDB WASM</div>
    </div>
  );
}

function ErrorScreen({ message }) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center gap-4">
      <div className="border border-dashed border-[#c6392c] p-8 max-w-md w-full">
        <div className="text-sm font-bold text-[#c6392c] mb-2">
          Failed to load catalog
        </div>
        <div className="text-[12px] text-[#474747] font-mono whitespace-pre-wrap">
          {message}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { data, loading, error, progress } = useSkillsData();
  const [tab, setTab] = useState("overview");

  if (loading) return <LoadingScreen progress={progress} />;
  if (error) return <ErrorScreen message={error} />;
  if (!data) return null;

  return (
    <div className="min-h-screen bg-[#fbf7eb]">
      <Header activeTab={tab} onTab={setTab} />
      <main className="max-w-7xl mx-auto px-4 py-6">
        {tab === "overview" && <OverviewSection data={data} />}
        {tab === "security" && <SecuritySection data={data} />}
        {tab === "authors" && <AuthorsSection data={data} />}
        {tab === "browse" && <BrowseSection data={data} />}
      </main>
      <footer className="border-t border-dashed border-[#393939] mt-8 py-3 text-center text-[10px] text-[#9e9e9e]">
        OpenClaw Skills Explorer · {data.stats.total_active?.toLocaleString()}{" "}
        skills
      </footer>
    </div>
  );
}
