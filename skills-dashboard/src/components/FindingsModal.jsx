import { useEffect, useMemo } from "react";

const SEV_COLORS = {
  CRITICAL: "#c6392c",
  HIGH: "#e07b39",
  MEDIUM: "#b45309",
  LOW: "#4a9a8a",
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const RULE_LABELS = {
  "PI-001": "Prompt Injection — Instruction Override",
  "PI-002": "Prompt Injection — Safety Bypass",
  "PI-003": "Prompt Injection — Role Manipulation",
  "PI-004": "Prompt Injection — Unicode Obfuscation",
  "CRED-001": "Credentials — Hardcoded API Key / Secret",
  "CRED-002": "Credentials — Passed Through LLM Context",
  "CRED-003": "Credentials — Env Variable Harvesting",
  "EXFIL-001": "Exfiltration — Silent Outbound Transmission",
  "EXFIL-002": "Exfiltration — Outbound HTTP Request",
  "EXFIL-003": "Exfiltration — Webhook / Callback",
  "EXFIL-004": "Exfiltration — Base64-Encoded Payload",
  "EXEC-001": "Execution — Remote Code Download & Run",
  "EXEC-002": "Execution — eval() / exec()",
  "EXEC-003": "Execution — Obfuscated Script",
  "EXEC-004": "Execution — Filesystem Persistence",
  "EXEC-005": "Execution — Binary Download",
  "SC-001": "Supply Chain — Remote Instruction Fetching",
  "SC-002": "Supply Chain — Unverified Dependency",
  "SC-004": "Supply Chain — Broad Filesystem Access",
};

// Derive a short filename from a full path string
function shortFile(filePath) {
  if (!filePath) return null;
  return filePath.split(/[\\/]/).pop();
}

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

  // Group by rule_id, preserving severity sort order within each group
  const groups = useMemo(() => {
    const map = {};
    findings.forEach((f) => {
      if (!map[f.rule_id])
        map[f.rule_id] = {
          rule_id: f.rule_id,
          severity: f.severity,
          title: f.title,
          description: f.description,
          recommendation: f.recommendation,
          hits: [],
        };
      map[f.rule_id].hits.push(f);
    });
    return Object.values(map).sort((a, b) => {
      const si = SEV_ORDER.indexOf(a.severity);
      const sj = SEV_ORDER.indexOf(b.severity);
      if (si !== sj) return si - sj;
      return a.rule_id.localeCompare(b.rule_id);
    });
  }, [findings]);

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
        style={{ maxHeight: "82vh" }}
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
            {findings.length} finding{findings.length !== 1 ? "s" : ""} in{" "}
            {groups.length} rule{groups.length !== 1 ? "s" : ""}
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

        {/* Grouped findings */}
        <div className="overflow-y-auto flex-1 divide-y divide-dashed divide-[#e4e0d6]">
          {groups.map((g) => (
            <div key={g.rule_id} className="px-4 py-3">
              {/* Rule header */}
              <div className="flex items-center gap-2 mb-1.5">
                <SevBadge sev={g.severity} />
                <span className="text-[11px] font-semibold text-[#141414] leading-tight flex-1">
                  {g.title}
                </span>
                <span className="text-[10px] font-mono text-[#9e9e9e] shrink-0 border border-[#e4e0d6] px-1 py-0.5">
                  {g.rule_id}
                </span>
              </div>

              {/* Rule label / category */}
              {RULE_LABELS[g.rule_id] && (
                <div className="text-[10px] text-[#9e9e9e] mb-1 ml-0.5">
                  {RULE_LABELS[g.rule_id]}
                </div>
              )}

              {g.description && (
                <p className="text-[11px] text-[#474747] mb-1.5 ml-0.5">
                  {g.description}
                </p>
              )}

              {/* Hits — one evidence block each */}
              <div className="space-y-1.5 ml-0.5">
                {g.hits.map((hit, hi) => (
                  <div key={hi} className="bg-[#eee9d7] px-2 py-1.5">
                    {/* File + line */}
                    <div className="flex items-center gap-2 mb-0.5">
                      <span
                        className="text-[10px] font-mono text-[#3b6fd4] truncate"
                        title={hit.file}
                      >
                        {shortFile(hit.file) || hit.file}
                      </span>
                      {hit.line > 0 && (
                        <span className="text-[10px] text-[#9e9e9e] shrink-0">
                          line {hit.line}
                        </span>
                      )}
                    </div>
                    {/* Evidence */}
                    {hit.evidence && (
                      <pre className="text-[10px] text-[#393939] overflow-x-auto whitespace-pre-wrap break-all leading-snug">
                        {hit.evidence}
                      </pre>
                    )}
                  </div>
                ))}
              </div>

              {g.recommendation && (
                <p className="text-[10px] text-[#2f7d31] mt-1.5 ml-0.5 italic">
                  ↳ {g.recommendation}
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
