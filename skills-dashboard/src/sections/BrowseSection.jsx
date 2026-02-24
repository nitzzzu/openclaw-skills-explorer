import { useState, useMemo, useEffect } from "react";
import { SectionTitle } from "../components/SectionTitle";
import { RiskBadge } from "../components/RiskBadge";
import { FindingsModal } from "../components/FindingsModal";
import { Info } from "lucide-react";

const PER_PAGE = 50;
const GH_BASE = "https://github.com/openclaw/skills/tree/main/skills/";

function fmt(s) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d) ? String(s) : d.toISOString().slice(0, 10);
}

function fmtSize(bytes) {
  if (!bytes) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const RISK_ORDER = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  CLEAN: 4,
  UNKNOWN: 5,
};

function SortIcon({ col, sortKey, sortDir }) {
  if (col !== sortKey) return <span className="text-[#ccc] ml-0.5">⇅</span>;
  return <span className="ml-0.5">{sortDir === "asc" ? "↑" : "↓"}</span>;
}

export function BrowseSection({ data, authorFilter }) {
  const { browseSkills, findingsBySkill } = data;

  const [query, setQuery] = useState(authorFilter || "");
  const [catFilter, setCatFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [sortKey, setSortKey] = useState("date_added");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(0);
  const [modal, setModal] = useState(null);
  const [descModal, setDescModal] = useState(null);

  useEffect(() => {
    if (authorFilter !== undefined) {
      setQuery(authorFilter);
      setPage(0);
    }
  }, [authorFilter]);

  const catList = useMemo(() => {
    const s = new Set(browseSkills.map((r) => r.category).filter(Boolean));
    return [...s].sort();
  }, [browseSkills]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return browseSkills.filter((r) => {
      if (
        q &&
        !(
          (r.skill_path || "").toLowerCase().includes(q) ||
          (r.skill_author || "").toLowerCase().includes(q) ||
          (r.skill_display_name || "").toLowerCase().includes(q) ||
          (r.skill_description || "").toLowerCase().includes(q)
        )
      )
        return false;
      if (catFilter && r.category !== catFilter) return false;
      if (riskFilter && r.level !== riskFilter) return false;
      return true;
    });
  }, [browseSkills, query, catFilter, riskFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let av = a[sortKey],
        bv = b[sortKey];
      if (sortKey === "date_added") {
        av = av ? new Date(av).getTime() : 0;
        bv = bv ? new Date(bv).getTime() : 0;
      } else if (
        [
          "findings",
          "file_count",
          "script_count",
          "md_count",
          "folder_size_bytes",
        ].includes(sortKey)
      ) {
        av = Number(av) || 0;
        bv = Number(bv) || 0;
      } else if (sortKey === "level") {
        av = RISK_ORDER[av] ?? 9;
        bv = RISK_ORDER[bv] ?? 9;
      } else {
        av = (av || "").toLowerCase();
        bv = (bv || "").toLowerCase();
      }
      return sortDir === "asc" ? (av > bv ? 1 : -1) : av < bv ? 1 : -1;
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.ceil(sorted.length / PER_PAGE);
  const paged = sorted.slice(page * PER_PAGE, (page + 1) * PER_PAGE);

  function handleSort(key) {
    if (key === sortKey) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir("asc");
    }
    setPage(0);
  }

  function filterByAuthor(author) {
    setQuery(author);
    setPage(0);
  }

  function resetFilters() {
    setQuery("");
    setCatFilter("");
    setRiskFilter("");
    setPage(0);
  }

  const COLS = [
    { key: "skill_path", label: "Skill", right: false },
    { key: "skill_author", label: "Author", right: false },
    { key: "category", label: "Category", right: false },
    { key: "level", label: "Risk", right: false },
    { key: "findings", label: "Findings", right: true },
    { key: "date_added", label: "Added", right: true },
    { key: "file_count", label: "Files", right: true },
    { key: "script_count", label: "Scripts", right: true },
    { key: "md_count", label: "Docs", right: true },
    { key: "folder_size_bytes", label: "Size", right: true },
  ];

  return (
    <div className="space-y-4">
      <SectionTitle
        sub={`${browseSkills.length.toLocaleString()} skills total`}
      >
        Skills Browser
      </SectionTitle>

      <div className="flex flex-wrap gap-2 items-center">
        <input
          type="text"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(0);
          }}
          placeholder="Search path, author, description…"
          className="border border-[#9e9e9e] bg-[#fbf7eb] px-2 py-1 text-[12px] font-mono w-72 outline-none focus:border-[#393939]"
        />
        <select
          value={catFilter}
          onChange={(e) => {
            setCatFilter(e.target.value);
            setPage(0);
          }}
          className="border border-[#9e9e9e] bg-[#fbf7eb] px-2 py-1 text-[12px] font-mono outline-none focus:border-[#393939]"
        >
          <option value="">All categories</option>
          {catList.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          value={riskFilter}
          onChange={(e) => {
            setRiskFilter(e.target.value);
            setPage(0);
          }}
          className="border border-[#9e9e9e] bg-[#fbf7eb] px-2 py-1 text-[12px] font-mono outline-none focus:border-[#393939]"
        >
          <option value="">All risk levels</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"].map(
            (r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ),
          )}
        </select>
        {(query || catFilter || riskFilter) && (
          <button
            onClick={resetFilters}
            className="px-2 py-1 text-[11px] font-semibold border border-dashed border-[#393939] hover:bg-[#eee9d7]"
          >
            Clear
          </button>
        )}
        <span className="text-[11px] text-[#9e9e9e] ml-1">
          {sorted.length.toLocaleString()} results
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-[11px] border-collapse">
          <thead>
            <tr className="border-b border-dashed border-[#393939]">
              {COLS.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  className={`py-1.5 pr-3 text-[#6b6b6b] font-semibold uppercase tracking-wide select-none cursor-pointer hover:text-[#141414]
                    ${col.right ? "text-right" : "text-left"}`}
                >
                  {col.label}
                  <SortIcon col={col.key} sortKey={sortKey} sortDir={sortDir} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paged.length === 0 && (
              <tr>
                <td colSpan={10} className="py-8 text-center text-[#9e9e9e]">
                  No skills match your filters.
                </td>
              </tr>
            )}
            {paged.map((row, i) => (
              <tr
                key={row.skill_path}
                className={`border-b border-[#e4e0d6] hover:bg-[#f4f0e4] transition-colors ${i % 2 === 1 ? "bg-[#f9f5ee]" : ""}`}
              >
                {/* Skill path + description */}
                <td className="py-1.5 pr-3 w-[28%]">
                  <span className="inline-flex items-center gap-1">
                    <a
                      href={`${GH_BASE}${row.skill_path}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-[#3b6fd4] hover:underline break-all leading-tight"
                    >
                      {row.skill_path.split("/").pop()}
                    </a>
                    {row.skill_description && (
                      <button
                        onClick={() =>
                          setDescModal({
                            name: row.skill_path.split("/").pop(),
                            text: row.skill_description,
                          })
                        }
                        className="text-[#c0bbb0] hover:text-[#3b6fd4] flex-shrink-0"
                        title="Show description"
                      >
                        <Info size={11} strokeWidth={2} />
                      </button>
                    )}
                  </span>
                </td>

                {/* Author — click to filter */}
                <td className="py-1.5 pr-3 w-[14%]">
                  <button
                    onClick={() => filterByAuthor(row.skill_author)}
                    className="font-mono text-[11px] text-[#474747] hover:text-[#3b6fd4] hover:underline text-left truncate block max-w-[110px]"
                    title={`Filter by ${row.skill_author}`}
                  >
                    {row.skill_author}
                  </button>
                </td>

                {/* Category */}
                <td className="py-1.5 pr-3 text-[#6b6b6b] truncate max-w-[120px]">
                  {row.category}
                </td>

                {/* Risk */}
                <td className="py-1.5 pr-3">
                  <RiskBadge level={row.level} />
                </td>

                {/* Findings */}
                <td className="py-1.5 pr-3 text-right">
                  {row.findings > 0 ? (
                    <button
                      onClick={() => setModal(row.skill_path)}
                      className="font-semibold tabular-nums hover:underline cursor-pointer"
                      style={{
                        color:
                          row.level === "CRITICAL"
                            ? "#c6392c"
                            : row.level === "HIGH"
                              ? "#e07b39"
                              : "#b45309",
                      }}
                    >
                      {row.findings}
                    </button>
                  ) : (
                    <span className="text-[#9e9e9e]">—</span>
                  )}
                </td>

                {/* Date */}
                <td className="py-1.5 text-right text-[#9e9e9e] tabular-nums">
                  {fmt(row.date_added)}
                </td>

                {/* Files */}
                <td className="py-1.5 pr-3 text-right tabular-nums text-[#6b6b6b]">
                  {row.file_count > 0 ? row.file_count : "—"}
                </td>

                {/* Scripts */}
                <td className="py-1.5 pr-3 text-right tabular-nums text-[#6b6b6b]">
                  {row.script_count > 0 ? row.script_count : "—"}
                </td>

                {/* Docs */}
                <td className="py-1.5 pr-3 text-right tabular-nums text-[#6b6b6b]">
                  {row.md_count > 0 ? row.md_count : "—"}
                </td>

                {/* Size */}
                <td className="py-1.5 text-right tabular-nums text-[#6b6b6b]">
                  {fmtSize(row.folder_size_bytes)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={() => setPage(0)}
            disabled={page === 0}
            className="px-2 py-1 text-[11px] border border-dashed border-[#393939] disabled:opacity-30 hover:bg-[#eee9d7]"
          >
            «
          </button>
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-2 py-1 text-[11px] border border-dashed border-[#393939] disabled:opacity-30 hover:bg-[#eee9d7]"
          >
            ← Prev
          </button>
          <span className="text-[11px] text-[#6b6b6b]">
            Page {page + 1} / {totalPages} · {sorted.length.toLocaleString()}{" "}
            skills
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="px-2 py-1 text-[11px] border border-dashed border-[#393939] disabled:opacity-30 hover:bg-[#eee9d7]"
          >
            Next →
          </button>
          <button
            onClick={() => setPage(totalPages - 1)}
            disabled={page >= totalPages - 1}
            className="px-2 py-1 text-[11px] border border-dashed border-[#393939] disabled:opacity-30 hover:bg-[#eee9d7]"
          >
            »
          </button>
        </div>
      )}

      {descModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          onClick={() => setDescModal(null)}
        >
          <div className="absolute inset-0 bg-black/40" />
          <div
            className="relative bg-[#fbf7eb] border border-[#393939] p-5 max-w-lg w-full mx-4 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between mb-3">
              <span className="font-mono font-semibold text-[13px] text-[#141414] break-all pr-4">
                {descModal.name}
              </span>
              <button
                onClick={() => setDescModal(null)}
                className="text-[#9e9e9e] hover:text-[#141414] text-lg leading-none flex-shrink-0"
              >
                ×
              </button>
            </div>
            <p className="text-[12px] text-[#474747] leading-relaxed">
              {descModal.text}
            </p>
          </div>
        </div>
      )}

      {modal && (
        <FindingsModal
          skillPath={modal}
          findings={findingsBySkill?.[modal] || []}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  );
}
