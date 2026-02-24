import { useState, useEffect } from 'react'
import { initializeDuckDb, insertParquet, runQuery, arrowToJSON } from 'duckdb-wasm-kit'

const q = (db, sql) => runQuery(db, sql).then(arrowToJSON)

export function useSkillsData() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState('Initializing DuckDB...')

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        setProgress('Starting DuckDB WASM...')
        const db = await initializeDuckDb({ debug: false })

        setProgress('Fetching skills data (1.3 MB)...')
        const [skillsBuf, findingsBuf] = await Promise.all([
          fetch(`${import.meta.env.BASE_URL}skills.parquet`).then(r => r.arrayBuffer()),
          fetch(`${import.meta.env.BASE_URL}findings.parquet`).then(r => r.arrayBuffer()),
        ])

        if (cancelled) return

        setProgress('Loading skills into DuckDB...')
        const skillsFile = new File([skillsBuf], 'skills.parquet')
        await insertParquet(db, skillsFile, 'skills')

        const findingsFile = new File([findingsBuf], 'findings.parquet')
        await insertParquet(db, findingsFile, 'findings')

        if (cancelled) return
        setProgress('Running analytics...')

        const [
          statsRow,
          monthly,
          categories,
          riskLevels,
          authors,
          riskiest,
          findingsBySev,
          findingsByRule,
          browseSkills,
          allFindings,
        ] = await Promise.all([
          q(db, `
            SELECT
              COUNT(*) FILTER (WHERE NOT is_deleted) AS total_active,
              COUNT(*) FILTER (WHERE is_deleted) AS total_deleted,
              COUNT(DISTINCT category) FILTER (WHERE NOT is_deleted) AS total_categories,
              COUNT(*) FILTER (WHERE scan_risk_level != 'UNKNOWN' AND NOT is_deleted) AS total_scanned,
              COUNT(*) FILTER (WHERE scan_risk_level IN ('CRITICAL','HIGH') AND NOT is_deleted) AS high_risk,
              COUNT(*) FILTER (WHERE is_blacklisted) AS blacklisted
            FROM skills
          `),
          q(db, `
            SELECT strftime('%Y-%m-%d', date_added::TIMESTAMP) AS day, COUNT(*) AS added
            FROM skills WHERE date_added IS NOT NULL AND NOT is_deleted
            GROUP BY 1 ORDER BY 1
          `),
          q(db, `
            SELECT category, COUNT(*) AS cnt
            FROM skills WHERE NOT is_deleted
            GROUP BY 1 ORDER BY 2 DESC LIMIT 20
          `),
          q(db, `
            SELECT scan_risk_level AS level, COUNT(*) AS cnt
            FROM skills WHERE NOT is_deleted
            GROUP BY 1 ORDER BY 2 DESC
          `),
          q(db, `
            SELECT skill_author, COUNT(*) AS cnt
            FROM skills WHERE NOT is_deleted
            GROUP BY 1 ORDER BY 2 DESC LIMIT 25
          `),
          q(db, `
            SELECT skill_path, skill_author, category, scan_risk_level AS level,
                   scan_findings_count AS findings, scan_date
            FROM skills
            WHERE scan_risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW','CLEAN')
              AND NOT is_deleted
            ORDER BY
              CASE scan_risk_level WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
              scan_findings_count DESC
            LIMIT 50
          `),
          q(db, `
            SELECT severity, COUNT(*) AS cnt
            FROM findings GROUP BY 1 ORDER BY cnt DESC
          `),
          q(db, `
            SELECT finding_category AS category, COUNT(*) AS cnt
            FROM findings GROUP BY 1 ORDER BY cnt DESC
          `),
          q(db, `
            SELECT skill_path, skill_name, skill_author, skill_display_name,
                   skill_description, category, scan_risk_level AS level,
                   scan_findings_count AS findings, date_added
            FROM skills WHERE NOT is_deleted
            ORDER BY date_added DESC NULLS LAST
          `),
          q(db, `
            SELECT skill_path, rule_id, severity, finding_category AS rule_cat,
                   title, description, line, evidence, recommendation
            FROM findings
            ORDER BY skill_path,
              CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
              line
          `),
        ])

        if (cancelled) return

        const rawStats = statsRow[0]
        const stats = Object.fromEntries(
          Object.entries(rawStats).map(([k, v]) => [k, typeof v === 'bigint' ? Number(v) : v])
        )

        setData({
          stats,
          monthly: monthly.map(r => ({ month: r.day, added: Number(r.added) })),
          categories: categories.map(r => ({ name: String(r.category), cnt: Number(r.cnt) })),
          riskLevels: riskLevels.map(r => ({ level: r.level, cnt: Number(r.cnt) })),
          authors: authors.map(r => ({ author: r.skill_author, cnt: Number(r.cnt) })),
          riskiest: riskiest.map(r => ({ ...r, findings: Number(r.findings) })),
          findingsBySev: findingsBySev.map(r => ({ name: r.severity, cnt: Number(r.cnt) })),
          findingsByRule: findingsByRule.map(r => ({ name: r.category, cnt: Number(r.cnt) })),
          browseSkills: browseSkills.map(r => ({ ...r, findings: Number(r.findings) })),
          findingsBySkill: allFindings.reduce((acc, r) => {
            if (!acc[r.skill_path]) acc[r.skill_path] = []
            acc[r.skill_path].push(r)
            return acc
          }, {}),
        })
        setLoading(false)
      } catch (e) {
        if (!cancelled) {
          console.error(e)
          setError(e.message || String(e))
          setLoading(false)
        }
      }
    }

    load()
    return () => { cancelled = true }
  }, [])

  return { data, loading, error, progress }
}
