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
      <div className="text-[10px] text-[#9e9e9e]">Powered by OpenClaw Hub</div>
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
  const [authorFilter, setAuthorFilter] = useState("");

  if (loading) return <LoadingScreen progress={progress} />;
  if (error) return <ErrorScreen message={error} />;
  if (!data) return null;

  function handleAuthorClick(author) {
    setAuthorFilter(author);
    setTab("browse");
  }

  function handleTabChange(t) {
    if (t !== "browse") setAuthorFilter("");
    setTab(t);
  }

  return (
    <div className="min-h-screen bg-[#fbf7eb]">
      <Header activeTab={tab} onTab={handleTabChange} />
      <main className="max-w-7xl mx-auto px-4 py-6">
        {tab === "overview" && <OverviewSection data={data} />}
        {tab === "security" && <SecuritySection data={data} />}
        {tab === "authors" && (
          <AuthorsSection data={data} onAuthorClick={handleAuthorClick} />
        )}
        {tab === "browse" && (
          <BrowseSection data={data} authorFilter={authorFilter} />
        )}
      </main>
      <footer className="border-t border-dashed border-[#393939] mt-8 py-3 text-center text-[10px] text-[#9e9e9e]">
        <span>
          ClawEye · {data.stats.total_active?.toLocaleString()} skills
        </span>
        <a
          href="https://github.com/nitzzzu/openclaw-skills-explorer"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 ml-3 hover:text-[#141414] transition-colors"
          aria-label="View on GitHub"
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="currentColor"
            aria-hidden="true"
          >
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
          </svg>
          <span>GitHub</span>
        </a>
      </footer>
    </div>
  );
}
