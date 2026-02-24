export function Header({ activeTab, onTab }) {
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "security", label: "Security" },
    { id: "authors", label: "Authors" },
    { id: "browse", label: "Browse" },
  ];

  return (
    <header className="border-b border-dashed border-[#393939] bg-[#fbf7eb] sticky top-0 z-10">
      <div className="max-w-7xl mx-auto px-4 flex items-center justify-between h-12">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-5 h-5 border border-dashed border-[#393939] flex items-center justify-center">
            <div className="w-2 h-2 bg-[#141414]" />
          </div>
          <span className="font-bold text-sm tracking-tight text-[#141414]">
            OpenClaw Skills Explorer
          </span>
          <span className="hidden sm:inline text-[10px] text-[#9e9e9e] border border-[#e4e0d6] px-1.5 py-0.5 rounded-sm">
            Agentic Catalog
          </span>
        </div>

        {/* Tabs */}
        <nav className="flex gap-0.5">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => onTab(tab.id)}
              className={`px-3 py-1 text-[12px] font-semibold border border-dashed transition-colors rounded-[0.2rem]
                ${
                  activeTab === tab.id
                    ? "border-[#141414] bg-[#141414] text-[#fbf7eb]"
                    : "border-transparent text-[#6b6b6b] hover:border-[#9e9e9e] hover:text-[#141414]"
                }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>
    </header>
  );
}
