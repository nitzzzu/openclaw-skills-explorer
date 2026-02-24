/** Compact author signal badge — tier pill + follower count with rich tooltip. */
export function AuthorSignal({ profile }) {
  if (!profile) return null;

  const { followers, public_repos, created_at, account_type } = profile;

  const ageYears = created_at
    ? (Date.now() - new Date(created_at).getTime()) / 31557600000
    : null;

  const { color, label } = getTier(account_type, followers, public_repos, ageYears);

  const tooltip = [
    profile.name || profile.username,
    profile.bio ? `"${profile.bio.slice(0, 80)}"` : null,
    `${fmtK(followers)} followers · ${fmtK(public_repos)} repos`,
    ageYears != null ? `Account age: ${ageYears.toFixed(1)}y` : null,
    profile.company ? `@ ${profile.company}` : null,
    profile.location || null,
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <span className="inline-flex items-center gap-[3px] ml-1" title={tooltip}>
      {label && (
        <span
          className="text-[8px] font-bold leading-none px-[3px] py-[1px] rounded-[2px]"
          style={{ color: "#fbf7eb", backgroundColor: color }}
        >
          {label}
        </span>
      )}
      <span className="text-[9px] text-[#9e9e9e] tabular-nums">
        {fmtK(followers)}
      </span>
    </span>
  );
}

/** Wider variant for leaderboard rows — shows more context. */
export function AuthorSignalWide({ profile }) {
  if (!profile) return null;

  const { followers, public_repos, created_at, account_type } = profile;

  const ageYears = created_at
    ? (Date.now() - new Date(created_at).getTime()) / 31557600000
    : null;

  const { color, label } = getTier(account_type, followers, public_repos, ageYears);

  const tooltip = [
    profile.name || profile.username,
    profile.bio ? `"${profile.bio.slice(0, 80)}"` : null,
    `${fmtK(followers)} followers · ${fmtK(public_repos)} repos`,
    ageYears != null ? `Account age: ${ageYears.toFixed(1)}y` : null,
    profile.company ? `@ ${profile.company}` : null,
    profile.location || null,
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <span
      className="inline-flex items-center gap-1 ml-1.5 text-[9px] tabular-nums"
      title={tooltip}
    >
      {label && (
        <span
          className="font-bold leading-none px-[3px] py-[1px] rounded-[2px]"
          style={{ color: "#fbf7eb", backgroundColor: color }}
        >
          {label}
        </span>
      )}
      <span className="text-[#9e9e9e]">{fmtK(followers)}★</span>
      <span className="text-[#b8b3a6]">{fmtK(public_repos)}r</span>
      {ageYears != null && (
        <span className="text-[#b8b3a6]">{ageYears.toFixed(0)}y</span>
      )}
    </span>
  );
}

function fmtK(n) {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

function getTier(account_type, followers, public_repos, ageYears) {
  if (account_type === "Organization")
    return { color: "#6b6b6b", label: "ORG" };
  if (account_type === "Bot")
    return { color: "#9e9e9e", label: "BOT" };
  if (followers >= 100 && public_repos >= 20 && ageYears >= 3)
    return { color: "#2f7d31", label: "TOP" };
  if (followers >= 10 && public_repos >= 5 && ageYears >= 1)
    return { color: "#4a9a8a", label: "OK" };
  if (ageYears < 0.5 && followers < 3 && public_repos <= 2)
    return { color: "#c6392c", label: "NEW" };
  if (followers < 3 && public_repos <= 3)
    return { color: "#b45309", label: "LOW" };
  return { color: "#9e9e9e", label: null };
}
