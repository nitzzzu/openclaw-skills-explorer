import { useCallback, useEffect, useState } from "react";
import useEmblaCarousel from "embla-carousel-react";
import { RiskBadge } from "./RiskBadge";
import { AuthorSignal } from "./AuthorSignal";
import { Github } from "lucide-react";

const GH_BASE = "https://github.com/openclaw/skills/tree/main/skills/";
const PAGE_SIZE = 20;

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

function StatCell({ label, value }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9px] uppercase tracking-widest text-[#9e9e9e]">
        {label}
      </span>
      <span className="text-[12px] tabular-nums text-[#474747]">{value}</span>
    </div>
  );
}

function SkillCard({ skill, findingsBySkill, authorProfiles, isSelected, onAuthorFilter, onFindingsClick }) {
  const profile = authorProfiles[skill.skill_author];
  const skillFindings = findingsBySkill?.[skill.skill_path] || [];
  const name = skill.skill_path.split("/").pop();

  return (
    <div
      style={{
        transform: isSelected ? "scale(1) translateY(0)" : "scale(0.94) translateY(6px)",
        opacity: isSelected ? 1 : 0.5,
        transition: "transform 0.25s cubic-bezier(.22,.68,0,.99), opacity 0.25s ease",
        boxShadow: isSelected ? "5px 5px 0 0 #393939" : "2px 2px 0 0 #9e9e9e",
      }}
      className={`bg-[#fbf7eb] border font-mono h-full flex flex-col ${
        isSelected ? "border-[#393939]" : "border-[#c5c0b5]"
      }`}
    >
      {/* Header */}
      <div className="p-4 border-b border-dashed border-[#c5c0b5]">
        <div className="flex items-start justify-between gap-2 mb-1.5">
          <a
            href={`${GH_BASE}${skill.skill_path}`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-semibold text-[14px] text-[#3b6fd4] hover:underline leading-tight break-all"
          >
            {name}
            {skill.skill_version && (
              <span className="text-[#9e9e9e] font-normal ml-1.5 text-[11px]">
                v{skill.skill_version.replace(/^v/i, "")}
              </span>
            )}
          </a>
          <div className="flex-shrink-0 mt-0.5">
            <RiskBadge level={skill.level} />
          </div>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-[#9e9e9e]">
          {skill.category || "—"}
        </span>
      </div>

      {/* Description */}
      <div className="p-4 border-b border-dashed border-[#c5c0b5] flex-1">
        {skill.skill_description ? (
          <p className="text-[12px] text-[#474747] leading-relaxed line-clamp-5">
            {skill.skill_description}
          </p>
        ) : (
          <p className="text-[12px] text-[#b8b3a6] italic">No description available.</p>
        )}
      </div>

      {/* Author row */}
      <div className="px-4 py-3 border-b border-dashed border-[#c5c0b5] flex items-center gap-2">
        <button
          onClick={() => onAuthorFilter?.(skill.skill_author)}
          className="text-[12px] text-[#474747] hover:text-[#3b6fd4] truncate max-w-[140px]"
        >
          {skill.skill_author}
        </button>
        <AuthorSignal profile={profile} />
        <a
          href={`https://github.com/${skill.skill_author}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#9e9e9e] hover:text-[#141414] ml-auto flex-shrink-0"
          title={`GitHub: ${skill.skill_author}`}
        >
          <Github size={13} strokeWidth={1.8} />
        </a>
      </div>

      {/* Stats grid */}
      <div className="px-4 py-3 grid grid-cols-3 gap-x-4 gap-y-3">
        <div className="flex flex-col gap-0.5">
          <span className="text-[9px] uppercase tracking-widest text-[#9e9e9e]">Findings</span>
          {skill.findings > 0 ? (
            <button
              onClick={() => skillFindings.length > 0 && onFindingsClick?.(skill.skill_path)}
              className="text-[12px] tabular-nums font-semibold text-left hover:underline w-fit"
              style={{
                color:
                  skill.level === "CRITICAL"
                    ? "#c6392c"
                    : skill.level === "HIGH"
                      ? "#e07b39"
                      : "#b45309",
              }}
            >
              {skill.findings}
            </button>
          ) : (
            <span className="text-[12px] tabular-nums text-[#9e9e9e]">—</span>
          )}
        </div>
        <StatCell label="Size" value={fmtSize(skill.folder_size_bytes)} />
        <StatCell label="Files" value={skill.file_count > 0 ? skill.file_count : "—"} />
        <StatCell label="Scripts" value={skill.script_count > 0 ? skill.script_count : "—"} />
        <StatCell label="Docs" value={skill.md_count > 0 ? skill.md_count : "—"} />
        <StatCell label="Added" value={fmt(skill.date_added)} />
      </div>
    </div>
  );
}

export function SkillCardCarousel({
  skills,
  findingsBySkill,
  authorProfiles = {},
  onAuthorFilter,
  onFindingsClick,
}) {
  const [carouselPage, setCarouselPage] = useState(0);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [canScrollPrev, setCanScrollPrev] = useState(false);
  const [canScrollNext, setCanScrollNext] = useState(false);

  const totalPages = Math.ceil(skills.length / PAGE_SIZE);
  const pageItems = skills.slice(carouselPage * PAGE_SIZE, (carouselPage + 1) * PAGE_SIZE);

  const [emblaRef, emblaApi] = useEmblaCarousel({
    align: "center",
    loop: false,
    dragFree: false,
    watchDrag: true,
  });

  const onSelect = useCallback(() => {
    if (!emblaApi) return;
    setSelectedIndex(emblaApi.selectedScrollSnap());
    setCanScrollPrev(emblaApi.canScrollPrev());
    setCanScrollNext(emblaApi.canScrollNext());
  }, [emblaApi]);

  useEffect(() => {
    if (!emblaApi) return;
    onSelect();
    emblaApi.on("select", onSelect);
    emblaApi.on("reInit", onSelect);
    return () => {
      emblaApi.off("select", onSelect);
      emblaApi.off("reInit", onSelect);
    };
  }, [emblaApi, onSelect]);

  // Reset to page 0 + card 0 when the skills list changes (filter/sort)
  useEffect(() => {
    setCarouselPage(0);
    setSelectedIndex(0);
  }, [skills]);

  // Re-init embla and jump to card 0 whenever the page changes
  useEffect(() => {
    if (!emblaApi) return;
    emblaApi.reInit();
    emblaApi.scrollTo(0, true);
    setSelectedIndex(0);
  }, [emblaApi, carouselPage]);

  const scrollPrev = useCallback(() => emblaApi?.scrollPrev(), [emblaApi]);
  const scrollNext = useCallback(() => emblaApi?.scrollNext(), [emblaApi]);

  function goToPage(p) {
    setCarouselPage(Math.max(0, Math.min(totalPages - 1, p)));
  }

  if (skills.length === 0) {
    return (
      <div className="py-16 text-center text-[#9e9e9e] font-mono text-[12px]">
        No skills match your filters.
      </div>
    );
  }

  const globalIndex = carouselPage * PAGE_SIZE + selectedIndex;

  return (
    <div className="relative select-none">
      {/* Global counter */}
      <div className="text-center text-[11px] text-[#9e9e9e] mb-3 tabular-nums">
        <span className="text-[#141414] font-semibold">{globalIndex + 1}</span>
        <span className="mx-1">/</span>
        <span>{skills.length.toLocaleString()}</span>
        {totalPages > 1 && (
          <span className="ml-2 text-[#b8b3a6]">
            · page {carouselPage + 1}/{totalPages}
          </span>
        )}
      </div>

      {/* Embla viewport — only renders PAGE_SIZE items */}
      <div className="overflow-hidden -mx-2" ref={emblaRef}>
        <div className="flex gap-3 px-2">
          {pageItems.map((skill, i) => (
            <div key={skill.skill_path} className="flex-none w-[88%] min-w-0">
              <SkillCard
                skill={skill}
                findingsBySkill={findingsBySkill}
                authorProfiles={authorProfiles}
                isSelected={i === selectedIndex}
                onAuthorFilter={onAuthorFilter}
                onFindingsClick={onFindingsClick}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Card nav row */}
      <div className="flex items-center justify-between mt-5 px-1">
        <button
          onClick={scrollPrev}
          disabled={!canScrollPrev}
          className="flex items-center gap-1.5 px-3 py-2 text-[11px] border border-dashed border-[#393939] disabled:opacity-20 hover:bg-[#eee9d7] font-mono"
        >
          ← Prev
        </button>

        {/* Dot indicators for within-page position */}
        <div className="flex items-center gap-1.5">
          {pageItems.slice(0, 7).map((_, i) => (
            <button
              key={i}
              onClick={() => emblaApi?.scrollTo(i)}
              className="rounded-full transition-all"
              style={{
                width: i === selectedIndex ? 8 : 5,
                height: i === selectedIndex ? 8 : 5,
                backgroundColor: i === selectedIndex ? "#393939" : "#c5c0b5",
              }}
            />
          ))}
          {pageItems.length > 7 && (
            <span className="text-[10px] text-[#9e9e9e] ml-0.5">…</span>
          )}
        </div>

        <button
          onClick={scrollNext}
          disabled={!canScrollNext}
          className="flex items-center gap-1.5 px-3 py-2 text-[11px] border border-dashed border-[#393939] disabled:opacity-20 hover:bg-[#eee9d7] font-mono"
        >
          Next →
        </button>
      </div>

      {/* Page nav row — only shown when there are multiple pages */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 px-1">
          <button
            onClick={() => goToPage(carouselPage - 1)}
            disabled={carouselPage === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-[11px] border border-[#393939] bg-[#f4f0e4] disabled:opacity-20 hover:bg-[#eee9d7] font-mono font-semibold"
          >
            « Prev 20
          </button>

          <span className="text-[10px] text-[#9e9e9e] tabular-nums">
            {carouselPage * PAGE_SIZE + 1}–{Math.min((carouselPage + 1) * PAGE_SIZE, skills.length)} of {skills.length.toLocaleString()}
          </span>

          <button
            onClick={() => goToPage(carouselPage + 1)}
            disabled={carouselPage >= totalPages - 1}
            className="flex items-center gap-1.5 px-3 py-2 text-[11px] border border-[#393939] bg-[#f4f0e4] disabled:opacity-20 hover:bg-[#eee9d7] font-mono font-semibold"
          >
            Next 20 »
          </button>
        </div>
      )}

      <p className="text-center text-[10px] text-[#b8b3a6] mt-3">
        swipe to explore · {skills.length.toLocaleString()} skills
      </p>
    </div>
  );
}
