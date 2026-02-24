import { useEffect } from "react";

const SEV_COLORS = {
  CRITICAL: "#c6392c",
  HIGH: "#e07b39",
  MEDIUM: "#b45309",
  LOW: "#4a9a8a",
};

const RULE_LABELS = {
  PI: "Prompt Injection",
  CRED: "Credentials Leak",
  EXFIL: "Data Exfiltration",
  EXEC: "Code Execution",
  SC: "Supply Chain",
};

function SevBadge({ sev }) {
  const c = SEV_COLORS[sev] || "#9e9e9e";
  return (
    <span
      style={{ color: c, borderColor: c }}
      className="inline-block px-1 py-0.5 text-[10px] font-bold border rounded-[0.2rem] shrink-0"
    >
      {sev}
    </span>
  );
}

export function FindingsModal({ skillPath, findings, onClose }) {
  // Close on Escape
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  const counts = findings.reduce((a, r) => {
    a[r.severity] = (a[r.severity] || 0) + 1;
    return a;
  }, {});

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-12 px-4 pb-8"
      style={{ background: "rgba(20,20,20,0.55)" }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-2xl bg-[#fbf7eb] border border-dashed border-[#393939] flex flex-col"
        style={{ maxHeight: "80vh" }}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 p-4 border-b border-dashed border-[#393939]">
          <div>
            <div className="text-[10px] uppercase tracking-wide text-[#6b6b6b] mb-0.5">
              Security Findings
            </div>
            <div className="font-bold text-sm font-mono text-[#3b6fd4] break-all">
              {skillPath}
            </div>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 text-[#6b6b6b] hover:text-[#141414] text-lg leading-none mt-0.5"
          >
            ✕
          </button>
        </div>

        {/* Summary bar */}
        <div className="flex flex-wrap gap-3 px-4 py-2.5 border-b border-dashed border-[#e4e0d6]">
          <span className="text-[11px] text-[#6b6b6b]">
            {findings.length} finding{findings.length !== 1 ? "s" : ""} total
          </span>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            .filter((s) => counts[s])
            .map((s) => (
              <span
                key={s}
                className="text-[11px]"
                style={{ color: SEV_COLORS[s] }}
              >
                {counts[s]} {s}
              </span>
            ))}
        </div>

        {/* Findings list */}
        <div className="overflow-y-auto flex-1 divide-y divide-dashed divide-[#e4e0d6]">
          {findings.map((f, i) => (
            <div key={i} className="px-4 py-3">
              <div className="flex items-start gap-2 mb-1">
                <SevBadge sev={f.severity} />
                <span className="text-[11px] font-semibold text-[#141414] leading-tight">
                  {f.title}
                </span>
                <span className="ml-auto text-[10px] text-[#9e9e9e] shrink-0">
                  {RULE_LABELS[f.rule_id] || f.rule_id}
                </span>
              </div>
              {f.description && (
                <p className="text-[11px] text-[#474747] mb-1 ml-0.5">
                  {f.description}
                </p>
              )}
              {f.evidence && (
                <div className="ml-0.5 mt-1">
                  <span className="text-[10px] uppercase text-[#9e9e9e] tracking-wide">
                    Evidence
                  </span>
                  <pre className="mt-0.5 text-[10px] bg-[#eee9d7] text-[#393939] p-1.5 overflow-x-auto whitespace-pre-wrap break-all leading-snug">
                    {f.line > 0 && (
                      <span className="text-[#9e9e9e]">L{f.line}: </span>
                    )}
                    {f.evidence}
                  </pre>
                </div>
              )}
              {f.recommendation && (
                <p className="text-[10px] text-[#2f7d31] mt-1 ml-0.5 italic">
                  ↳ {f.recommendation}
                </p>
              )}
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 border-t border-dashed border-[#393939] flex justify-end">
          <button
            onClick={onClose}
            className="px-3 py-1 text-[11px] font-semibold border border-dashed border-[#393939] hover:bg-[#eee9d7]"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
