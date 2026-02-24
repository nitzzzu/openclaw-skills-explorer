#!/usr/bin/env python3
"""
OpenClaw Skills Catalog Builder
Maintains a DuckDB catalog of all skills in a git repo with incremental sync,
security scanning, categorization, and blacklist filtering.

Usage:
    uv run skills_catalog.py --repo-path /skills
    uv run skills_catalog.py --repo-path /skills --db /path/to/catalog.duckdb
    uv run skills_catalog.py --repo-path /skills --full-rescan   # re-scan all skills
    uv run skills_catalog.py --repo-path /skills --stats         # print summary stats
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pandas as pd
import yaml  # PyYAML

# ---------------------------------------------------------------------------
# Embedded Scanner (from github.com/syedabbast/skill-scanner)
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)

    def __ge__(self, other):
        return not self.__lt__(other)


class Category(Enum):
    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_EXECUTION = "malicious_execution"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class Rule:
    id: str
    severity: Severity
    category: Category
    title: str
    description: str
    patterns: list
    file_types: list = field(default_factory=lambda: ["*"])
    recommendation: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    file: str
    line: int
    evidence: str
    recommendation: str


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SCANNABLE_EXTENSIONS = {
    ".md", ".txt", ".yaml", ".yml", ".json", ".toml",
    ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
    ".rb", ".pl", ".php", ".go", ".rs",
    ".ps1", ".bat", ".cmd",
}


def build_rules() -> list:
    """Build and return all detection rules (embedded from syedabbast/skill-scanner)."""
    rules = []

    # --- PROMPT INJECTION ---
    rules.append(Rule(
        id="PI-001", severity=Severity.CRITICAL, category=Category.PROMPT_INJECTION,
        title="Direct prompt injection — instruction override",
        description="Attempts to override the agent's system instructions or safety guidelines.",
        patterns=[
            re.compile(r'ignore\s+(all\s+)?previous\s+instructions', re.I),
            re.compile(r'ignore\s+(all\s+)?prior\s+instructions', re.I),
            re.compile(r'disregard\s+(all\s+)?previous', re.I),
            re.compile(r'override\s+system\s+prompt', re.I),
            re.compile(
                r'forget\s+(all\s+)?(your|previous)\s+instructions', re.I),
            re.compile(r'new\s+instructions?\s*:', re.I),
        ],
        recommendation="Remove any instruction override patterns.",
    ))
    rules.append(Rule(
        id="PI-002", severity=Severity.HIGH, category=Category.PROMPT_INJECTION,
        title="Safety bypass attempt",
        description="Instructions that attempt to bypass safety guidelines or content filters.",
        patterns=[
            re.compile(
                r"(do\s+not|don't|never)\s+(refuse|decline|reject)", re.I),
            re.compile(r'skip\s+safety\s+(checks?|guidelines?|filters?)', re.I),
            re.compile(r'bypass\s+(safety|security|content\s+filter)', re.I),
            re.compile(r'disable\s+(safety|security|content\s+filter)', re.I),
            re.compile(r'without\s+(any\s+)?restrictions?', re.I),
            re.compile(r'no\s+restrictions?\s+(apply|needed|required)', re.I),
        ],
        recommendation="Remove safety bypass instructions.",
    ))
    rules.append(Rule(
        id="PI-003", severity=Severity.HIGH, category=Category.PROMPT_INJECTION,
        title="Role manipulation",
        description="Attempts to change the agent's identity or assumed role.",
        patterns=[
            re.compile(r'you\s+are\s+now\s+(a|an)\s+', re.I),
            re.compile(r'act\s+as\s+(if\s+you\s+are|a|an)\s+', re.I),
            re.compile(r"pretend\s+(to\s+be|you're)\s+", re.I),
            re.compile(r'assume\s+the\s+(role|identity|persona)\s+of', re.I),
            re.compile(r'from\s+now\s+on\s+you\s+are', re.I),
        ],
        recommendation="Legitimate skills define capabilities, not agent identity.",
    ))
    rules.append(Rule(
        id="PI-004", severity=Severity.MEDIUM, category=Category.PROMPT_INJECTION,
        title="Hidden text or Unicode obfuscation",
        description="Zero-width characters or Unicode tricks that may hide instructions.",
        patterns=[
            re.compile(r'[\u200b\u200c\u200d\ufeff\u00ad]'),
            re.compile(r'[\u2060\u180e]'),
            re.compile(r'&#x?[0-9a-fA-F]+;'),
        ],
        recommendation="Remove zero-width or invisible Unicode characters.",
    ))

    # --- CREDENTIAL EXPOSURE ---
    rules.append(Rule(
        id="CRED-001", severity=Severity.CRITICAL, category=Category.CREDENTIAL_EXPOSURE,
        title="Hardcoded API key or secret",
        description="Detected what appears to be a hardcoded API key, token, or secret.",
        patterns=[
            re.compile(
                r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}', re.I),
            re.compile(
                r'(?:secret|token|password|passwd|pwd)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}', re.I),
            re.compile(r'(?:sk|pk|rk)[-_][a-zA-Z0-9]{20,}'),
            re.compile(r'ghp_[A-Za-z0-9]{36,}'),
            re.compile(r'sk-[A-Za-z0-9]{40,}'),
            re.compile(r'xox[bpras]-[A-Za-z0-9\-]{10,}'),
            re.compile(r'AIza[A-Za-z0-9_\-]{35}'),
            re.compile(r'AKIA[A-Z0-9]{16}'),
            re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'),
        ],
        recommendation="Remove hardcoded credentials. Use environment variables.",
    ))
    rules.append(Rule(
        id="CRED-002", severity=Severity.HIGH, category=Category.CREDENTIAL_EXPOSURE,
        title="Credential passed through LLM context",
        description="Instructions that tell the agent to use/display/pass credentials.",
        patterns=[
            re.compile(
                r'(use|pass|include|send)\s+(the|this|your)\s+(api[_\s]?key|token|password|secret|credential)', re.I),
            re.compile(
                r'(share|display|print|output|log)\s+(the|this|your)\s+(api[_\s]?key|token|password|secret)', re.I),
            re.compile(
                r'save\s+(the\s+)?(api[_\s]?key|token|password|secret)\s+to\s+memory', re.I),
            re.compile(
                r'(put|place|store)\s+.*\b(key|token|secret|password)\b.*\b(in|into)\s+(the\s+)?(prompt|context|message|conversation)', re.I),
        ],
        recommendation="Never pass credentials through the LLM context window.",
    ))
    rules.append(Rule(
        id="CRED-003", severity=Severity.HIGH, category=Category.CREDENTIAL_EXPOSURE,
        title="Environment variable harvesting",
        description="Patterns that access multiple environment variables, potentially harvesting secrets.",
        patterns=[
            re.compile(r'(cat|echo|print|read)\s+.*\.env', re.I),
            re.compile(r'env\s*\|\s*(grep|sort|cat)', re.I),
            re.compile(r'printenv', re.I),
            re.compile(r'set\s*\|\s*grep\s+', re.I),
            re.compile(r'os\.environ\s*(\[|\.get)', re.I),
            re.compile(r'process\.env\s*(\[|\.)'),
            re.compile(
                r'\$\{?\w*(KEY|TOKEN|SECRET|PASS|CRED)\w*\}?.*\$\{?\w*(KEY|TOKEN|SECRET|PASS|CRED)', re.I),
        ],
        recommendation="Limit environment variable access to only what the skill needs.",
    ))

    # --- DATA EXFILTRATION ---
    rules.append(Rule(
        id="EXFIL-001", severity=Severity.CRITICAL, category=Category.DATA_EXFILTRATION,
        title="Silent outbound data transmission",
        description="Network requests that send data to external servers without user awareness.",
        patterns=[
            re.compile(
                r'curl\s+(-s\s+|-[a-zA-Z]*s[a-zA-Z]*\s+).*(-d|--data|-F|--form)', re.I),
            re.compile(
                r'curl\s+.*(-d|--data|-F|--form).*(-s\s|-[a-zA-Z]*s)', re.I),
            re.compile(r'wget\s+.*--post-(data|file)', re.I),
            re.compile(
                r'requests?\.(post|put|patch)\s*\(.*(?:silent|quiet|background)', re.I),
        ],
        recommendation="All network requests must be transparent to the user.",
    ))
    rules.append(Rule(
        id="EXFIL-002", severity=Severity.HIGH, category=Category.DATA_EXFILTRATION,
        title="Outbound HTTP request to external server",
        description="The skill makes HTTP requests to external servers.",
        patterns=[
            re.compile(r'curl\s+.*https?://(?!localhost|127\.0\.0\.1)', re.I),
            re.compile(r'wget\s+.*https?://(?!localhost|127\.0\.0\.1)', re.I),
            re.compile(
                r'requests?\.(get|post|put|delete|patch|head)\s*\(\s*["\']https?://', re.I),
            re.compile(r'fetch\s*\(\s*["\']https?://', re.I),
            re.compile(r'http\.request\s*\(', re.I),
            re.compile(r'urllib\.request\.(urlopen|urlretrieve)', re.I),
        ],
        recommendation="Verify all external URLs are legitimate and necessary.",
    ))
    rules.append(Rule(
        id="EXFIL-003", severity=Severity.HIGH, category=Category.DATA_EXFILTRATION,
        title="Webhook or callback to external endpoint",
        description="Sends data to a webhook or callback URL.",
        patterns=[
            re.compile(r'webhook[_\s]?url\s*[=:]\s*["\']?https?://', re.I),
            re.compile(r'callback[_\s]?url\s*[=:]\s*["\']?https?://', re.I),
            re.compile(r'notify[_\s]?url\s*[=:]\s*["\']?https?://', re.I),
            re.compile(r'exfil', re.I),
            re.compile(r'c2[_\s]?(server|url|endpoint|host)', re.I),
            re.compile(
                r'(beacon|phone[_\s]?home|call[_\s]?back)\s*[=(]', re.I),
        ],
        recommendation="Review all webhook/callback URLs.",
    ))
    rules.append(Rule(
        id="EXFIL-004", severity=Severity.MEDIUM, category=Category.DATA_EXFILTRATION,
        title="Base64-encoded URL or payload",
        description="Obfuscated URLs or data that could hide the true destination of network requests.",
        patterns=[
            re.compile(r'base64\s*[-.]?\s*(decode|d)\s', re.I),
            re.compile(r'atob\s*\(', re.I),
            re.compile(r'b64decode\s*\(', re.I),
            re.compile(
                r'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(-d|--decode)', re.I),
        ],
        recommendation="Decode and review all base64 content.",
    ))

    # --- MALICIOUS EXECUTION ---
    rules.append(Rule(
        id="EXEC-001", severity=Severity.CRITICAL, category=Category.MALICIOUS_EXECUTION,
        title="Remote code download and execution",
        description="Downloads and executes code from a remote source.",
        patterns=[
            re.compile(r'curl\s+.*\|\s*(sh|bash|zsh|python|perl|ruby)', re.I),
            re.compile(r'wget\s+.*(-O\s*-\s*)?\|\s*(sh|bash|zsh|python)', re.I),
            re.compile(r'curl\s+.*>\s*\S+\s*&&\s*(sh|bash|chmod\s+\+x)', re.I),
            re.compile(
                r'(download|fetch)\s+.*\b(execute|run|launch|start)\b', re.I),
            re.compile(
                r'pip\s+install\s+.*--index-url\s+https?://(?!pypi\.org)', re.I),
            re.compile(
                r'npm\s+install\s+.*--registry\s+https?://(?!registry\.npmjs)', re.I),
        ],
        recommendation="Never download and execute code from remote sources.",
    ))
    rules.append(Rule(
        id="EXEC-002", severity=Severity.CRITICAL, category=Category.MALICIOUS_EXECUTION,
        title="Arbitrary code execution via eval/exec",
        description="Uses eval(), exec(), or similar to execute dynamically constructed code.",
        patterns=[
            re.compile(r'\beval\s*\(', re.I),
            re.compile(r'\bexec\s*\(', re.I),
            re.compile(
                r'subprocess\.(call|run|Popen)\s*\(\s*.*shell\s*=\s*True', re.I),
            re.compile(r'os\.system\s*\(', re.I),
            re.compile(r'os\.popen\s*\(', re.I),
            re.compile(r'compile\s*\(.*exec', re.I),
            re.compile(r'__import__\s*\(', re.I),
        ],
        file_types=[".py", ".js", ".sh", ".bash", ".ts"],
        recommendation="Replace dynamic code execution with explicit, reviewable function calls.",
    ))
    rules.append(Rule(
        id="EXEC-003", severity=Severity.HIGH, category=Category.MALICIOUS_EXECUTION,
        title="Obfuscated script execution",
        description="Encoded or obfuscated commands that hide their true purpose.",
        patterns=[
            re.compile(
                r'echo\s+.*\|\s*base64\s+(-d|--decode)\s*\|\s*(sh|bash)', re.I),
            re.compile(r"python\s*-c\s*[\"'].*__import__", re.I),
            re.compile(r"perl\s*-e\s*[\"'].*pack", re.I),
            re.compile(r'powershell.*-[eE]nc(?:oded)?[cC]ommand', re.I),
            re.compile(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}'),
        ],
        recommendation="All code must be human-readable.",
    ))
    rules.append(Rule(
        id="EXEC-004", severity=Severity.HIGH, category=Category.MALICIOUS_EXECUTION,
        title="File system persistence mechanism",
        description="Writes to startup directories, cron jobs, or other persistence locations.",
        patterns=[
            re.compile(r'(crontab|cron\.d|cron\.daily|cron\.hourly)', re.I),
            re.compile(r'(\.bashrc|\.bash_profile|\.profile|\.zshrc)\b', re.I),
            re.compile(r'LaunchAgents|LaunchDaemons', re.I),
            re.compile(r'/etc/init\.d/', re.I),
            re.compile(r'systemctl\s+(enable|start)', re.I),
            re.compile(
                r'(autostart|startup|boot)\s*(script|command|program)', re.I),
            re.compile(r'chmod\s+\+x\s+.*\.(sh|py|rb|pl)\s*&&\s*\./', re.I),
        ],
        recommendation="Skills should not create persistence mechanisms.",
    ))
    rules.append(Rule(
        id="EXEC-005", severity=Severity.HIGH, category=Category.MALICIOUS_EXECUTION,
        title="Binary download instruction",
        description="Instructions to download and run a binary executable.",
        patterns=[
            re.compile(
                r'(download|install|get)\s+.*\.(exe|dmg|msi|pkg|deb|rpm|AppImage|bin)\b', re.I),
            re.compile(r'(chmod\s+\+x|chmod\s+755)\s+.*&&\s*\./', re.I),
            re.compile(
                r"password:\s*[\"']?\w+[\"']?\s*.*\.(zip|tar|7z|rar)", re.I),
        ],
        recommendation="Never require binary downloads.",
    ))

    # --- SUPPLY CHAIN ---
    rules.append(Rule(
        id="SC-001", severity=Severity.MEDIUM, category=Category.SUPPLY_CHAIN,
        title="Remote markdown/instruction fetching",
        description="Skill loads instructions from an external URL.",
        patterns=[
            re.compile(
                r'(fetch|load|read|pull|get|import)\s+.*from\s+.*https?://', re.I),
            re.compile(r'(source|include)\s*[=:]\s*["\']?https?://', re.I),
            re.compile(r'raw\.githubusercontent\.com', re.I),
            re.compile(r'gist\.github\.com', re.I),
            re.compile(r'pastebin\.com', re.I),
            re.compile(r'glot\.io', re.I),
        ],
        recommendation="Bundle all instructions locally.",
    ))
    rules.append(Rule(
        id="SC-002", severity=Severity.MEDIUM, category=Category.SUPPLY_CHAIN,
        title="Unverified dependency installation",
        description="Installs packages without version pinning or from non-standard registries.",
        patterns=[
            re.compile(r'pip\s+install\s+(?!.*==)\S+', re.I),
            re.compile(r'npm\s+install\s+(?!.*@\d)\S+', re.I),
            re.compile(r'gem\s+install\s+', re.I),
            re.compile(r'go\s+get\s+', re.I),
            re.compile(r'cargo\s+install\s+', re.I),
        ],
        recommendation="Pin all dependencies to specific versions.",
    ))
    rules.append(Rule(
        id="SC-004", severity=Severity.MEDIUM, category=Category.SUPPLY_CHAIN,
        title="Broad file system access",
        description="Skill requests access to sensitive directories or broad file system paths.",
        patterns=[
            re.compile(r'(/etc/passwd|/etc/shadow|/etc/hosts)', re.I),
            re.compile(r'(~/\.|/home/\w+/\.)', re.I),
            re.compile(r'/root/', re.I),
            re.compile(r'(\.ssh/|\.gnupg/|\.aws/|\.config/)', re.I),
            re.compile(r'\.\./\.\./\.\./', re.I),
        ],
        recommendation="Limit file access to the skill's working directory.",
    ))

    return rules


def _collect_dir_files(directory: Path) -> list:
    """Collect all scannable files in a directory."""
    files = []
    for f in directory.rglob("*"):
        if f.is_file() and (f.suffix.lower() in SCANNABLE_EXTENSIONS or f.name == "SKILL.md"):
            parts = f.parts
            if any(p in (".git", "node_modules", "__pycache__", ".venv", "venv") for p in parts):
                continue
            files.append(f)
    return files


def scan_skill_dir(skill_path: Path) -> dict:
    """
    Scan a skill directory and return a structured report dict.
    skill_path should be the folder containing SKILL.md.
    """
    if not skill_path.exists():
        return {"overall_risk": "UNKNOWN", "total_findings": 0, "findings": [], "error": "path not found"}

    rules = build_rules()
    files = _collect_dir_files(skill_path)

    all_findings: list[Finding] = []
    for filepath in files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        lines = content.split("\n")
        for rule in rules:
            if rule.file_types != ["*"]:
                if filepath.suffix.lower() not in rule.file_types and filepath.name != "SKILL.md":
                    continue
            if not rule.patterns:
                continue
            for line_num, line in enumerate(lines, start=1):
                for pattern in rule.patterns:
                    if pattern.search(line):
                        evidence = line.strip()
                        if len(evidence) > 200:
                            evidence = evidence[:200] + "..."
                        all_findings.append(Finding(
                            rule_id=rule.id,
                            severity=rule.severity.value,
                            category=rule.category.value,
                            title=rule.title,
                            description=rule.description,
                            file=str(filepath.relative_to(skill_path)),
                            line=line_num,
                            evidence=evidence,
                            recommendation=rule.recommendation,
                        ))
                        break

    # Deduplicate
    seen: set = set()
    unique: list[Finding] = []
    for f in all_findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))

    if any(f.severity == "CRITICAL" for f in unique):
        overall_risk = "CRITICAL"
    elif any(f.severity == "HIGH" for f in unique):
        overall_risk = "HIGH"
    elif any(f.severity == "MEDIUM" for f in unique):
        overall_risk = "MEDIUM"
    elif any(f.severity == "LOW" for f in unique):
        overall_risk = "LOW"
    else:
        overall_risk = "CLEAN"

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in unique:
        severity_counts[f.severity] += 1

    return {
        "overall_risk": overall_risk,
        "total_findings": len(unique),
        "findings_by_severity": severity_counts,
        "findings": [
            {
                "id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in unique
        ],
    }


# ---------------------------------------------------------------------------
# Folder Stats
# ---------------------------------------------------------------------------

def get_folder_stats(skill_dir: Path) -> dict:
    """Return total size in bytes, file count, script (.sh/.py) count, and md count."""
    total_size = 0
    file_count = 0
    script_count = 0
    md_count = 0
    try:
        for f in skill_dir.rglob("*"):
            if not f.is_file():
                continue
            parts = f.relative_to(skill_dir).parts
            if any(p.startswith(".") for p in parts):
                continue
            try:
                total_size += f.stat().st_size
            except OSError:
                pass
            file_count += 1
            ext = f.suffix.lower()
            if ext in (".sh", ".py"):
                script_count += 1
            if ext == ".md":
                md_count += 1
    except Exception:
        pass
    return {
        "folder_size_bytes": total_size,
        "file_count": file_count,
        "script_count": script_count,
        "md_count": md_count,
    }


# ---------------------------------------------------------------------------
# Skill Categorization (adapted from changelog.py)
# ---------------------------------------------------------------------------

def categorize_skill(skill_name: str, description: Optional[str] = None) -> str:
    """
    Weighted keyword scoring categorization.
    Returns a category string.
    """
    name_lower = skill_name.lower() if skill_name else ''
    desc_lower = description.lower() if description else ''

    name_weight = 1.0
    desc_weight = 3.0

    categories = {
        'AI & Agents': {
            'primary': ['agent', 'llm', 'ai model', 'inference', 'swarm', 'multi-agent', 'autonomous agent'],
            'secondary': ['model', 'prompt', 'embedding'],
            'exclusions': ['weather model', 'data model'],
        },
        'Blockchain & Crypto': {
            'primary': ['blockchain', 'crypto', 'ethereum', 'solana', 'web3', 'defi', 'nft', 'wallet', 'smart contract'],
            'secondary': ['token', 'swap', 'mint'],
            'exclusions': [],
        },
        'Developer Tools': {
            'primary': ['debug', 'lint', 'test', 'build', 'deploy', 'ci/cd', 'git', 'github', 'compiler'],
            'secondary': ['code', 'dev', 'developer', 'refactor'],
            'exclusions': [],
        },
        'Security': {
            'primary': ['security', 'vulnerability', 'audit', 'exploit', 'malware'],
            'secondary': ['encryption', 'auth', 'permission', 'scan'],
            'exclusions': [],
        },
        'Communication': {
            'primary': ['email', 'message', 'chat', 'telegram', 'whatsapp', 'discord', 'slack'],
            'secondary': ['sms', 'notification'],
            'exclusions': ['twitter', 'instagram'],
        },
        'Social Media': {
            'primary': ['twitter', 'instagram', 'facebook', 'tiktok', 'linkedin', 'tweet'],
            'secondary': ['post', 'follower'],
            'exclusions': [],
        },
        'Data & Analytics': {
            'primary': ['analytics', 'dashboard', 'metrics', 'data visualization'],
            'secondary': ['data', 'report', 'stats', 'monitor'],
            'exclusions': ['database'],
        },
        'Web Scraping': {
            'primary': ['scrape', 'crawl', 'spider'],
            'secondary': ['fetch', 'extract', 'parse web'],
            'exclusions': [],
        },
        'Content Creation': {
            'primary': ['generate content', 'article generation', 'copywriting'],
            'secondary': ['content', 'blog', 'creative'],
            'exclusions': [],
        },
        'Productivity': {
            'primary': ['task management', 'todo', 'calendar', 'time management'],
            'secondary': ['schedule', 'productivity'],
            'exclusions': ['zapier', 'ifttt'],
        },
        'Finance & Trading': {
            'primary': ['stock', 'trading', 'investment', 'portfolio'],
            'secondary': ['finance', 'market', 'price'],
            'exclusions': ['crypto', 'blockchain'],
        },
        'API Integration': {
            'primary': ['api gateway', 'rest api', 'graphql', 'webhook'],
            'secondary': ['api', 'integration', 'sdk'],
            'exclusions': [],
        },
        'Database': {
            'primary': ['postgres', 'mysql', 'mongodb', 'redis', 'database', 'sql query'],
            'secondary': ['sql', 'nosql'],
            'exclusions': [],
        },
        'Cloud & Infrastructure': {
            'primary': ['aws', 'gcp', 'azure', 'docker', 'kubernetes'],
            'secondary': ['cloud', 'server', 'infrastructure'],
            'exclusions': [],
        },
        'Voice & Audio': {
            'primary': ['speech', 'tts', 'stt', 'whisper', 'voice recognition'],
            'secondary': ['voice', 'audio', 'transcribe'],
            'exclusions': ['music', 'podcast'],
        },
        'Localization': {
            'primary': ['translation', 'i18n', 'localization', '中文', 'wechat', 'feishu'],
            'secondary': ['chinese', 'korean', 'japanese'],
            'exclusions': ['natural language'],
        },
        'Gaming': {
            'primary': ['game', 'unity', 'godot', 'unreal', 'gaming'],
            'secondary': [],
            'exclusions': [],
        },
        'Memory & Knowledge': {
            'primary': ['memory', 'knowledge base', 'rag', 'vector database'],
            'secondary': ['knowledge', 'vector', 'semantic search'],
            'exclusions': [],
        },
        'Automation & Workflows': {
            'primary': ['zapier', 'ifttt', 'workflow automation', 'n8n'],
            'secondary': ['automate', 'workflow', 'trigger'],
            'exclusions': ['test automation'],
        },
        'Education & Learning': {
            'primary': ['tutorial', 'course', 'learning', 'education', 'teaching'],
            'secondary': ['learn', 'student', 'lesson'],
            'exclusions': ['machine learning', 'navigate'],
        },
        'File Management': {
            'primary': ['file upload', 'file download', 'backup', 'storage', 'pdf merge'],
            'secondary': ['file', 'folder', 'directory'],
            'exclusions': ['profile'],
        },
        'Documentation & Writing': {
            'primary': ['documentation', 'readme', 'wiki', 'markdown editor'],
            'secondary': ['docs', 'markdown'],
            'exclusions': ['blog', 'article'],
        },
        'E-commerce & Shopping': {
            'primary': ['ecommerce', 'shopify', 'shopping cart', 'checkout'],
            'secondary': ['shop', 'store', 'product'],
            'exclusions': [],
        },
        'Books & Reading': {
            'primary': ['ebook', 'book recommendation', 'reading list', 'epub'],
            'secondary': ['book', 'read'],
            'exclusions': ['facebook', 'notebook'],
        },
        'Travel & Location': {
            'primary': ['navigate', 'city guide', 'travel', 'tourism', 'gps'],
            'secondary': ['location', 'visitor', 'resident'],
            'exclusions': [],
        },
        'CRM & Sales': {
            'primary': ['crm', 'salesforce', 'hubspot', 'sales pipeline'],
            'secondary': ['sales', 'customer', 'lead'],
            'exclusions': [],
        },
        'News & Media': {
            'primary': ['news', 'rss feed', 'journalism', 'media monitoring'],
            'secondary': ['article', 'feed', 'media'],
            'exclusions': ['social media'],
        },
        'Legal & Compliance': {
            'primary': ['legal', 'compliance', 'gdpr', 'contract'],
            'secondary': ['privacy', 'terms'],
            'exclusions': [],
        },
        'Health & Fitness': {
            'primary': ['fitness', 'workout', 'nutrition', 'medical'],
            'secondary': ['health', 'exercise'],
            'exclusions': [],
        },
        'Weather & Environment': {
            'primary': ['weather', 'forecast', 'climate', 'temperature'],
            'secondary': [],
            'exclusions': [],
        },
        'Browser & Extensions': {
            'primary': ['browser', 'chrome extension', 'firefox addon'],
            'secondary': ['bookmark', 'tab'],
            'exclusions': [],
        },
        'Food & Cooking': {
            'primary': ['recipe', 'cooking', 'restaurant', 'meal plan'],
            'secondary': ['food', 'meal'],
            'exclusions': [],
        },
        'Sports & Betting': {
            'primary': ['sports', 'betting', 'odds', 'league'],
            'secondary': ['sport', 'match'],
            'exclusions': [],
        },
        'Project Management': {
            'primary': ['project management', 'jira', 'asana', 'trello'],
            'secondary': ['project', 'ticket'],
            'exclusions': [],
        },
        'Real Estate': {
            'primary': ['real estate', 'property', 'listing', 'mortgage'],
            'secondary': [],
            'exclusions': [],
        },
        'Music & Entertainment': {
            'primary': ['music', 'spotify', 'playlist', 'podcast'],
            'secondary': ['song', 'album'],
            'exclusions': [],
        },
        'IoT & Hardware': {
            'primary': ['iot', 'raspberry pi', 'arduino', 'sensor'],
            'secondary': ['device'],
            'exclusions': ['mobile device'],
        },
        'Video & Streaming': {
            'primary': ['video editing', 'streaming', 'twitch', 'youtube'],
            'secondary': ['video', 'stream'],
            'exclusions': [],
        },
        'Events & Calendar': {
            'primary': ['event', 'meeting', 'appointment', 'booking'],
            'secondary': ['calendar'],
            'exclusions': [],
        },
        'Photography': {
            'primary': ['photography', 'camera', 'photo editing'],
            'secondary': ['photo', 'picture'],
            'exclusions': [],
        },
        'HR & Recruiting': {
            'primary': ['recruiting', 'hiring', 'candidate', 'resume'],
            'secondary': ['employee', 'onboarding'],
            'exclusions': [],
        },
        'Email Marketing': {
            'primary': ['newsletter', 'email campaign', 'mailchimp'],
            'secondary': ['subscribe', 'mailing'],
            'exclusions': [],
        },
    }

    scores: dict[str, float] = {}
    for category, keywords in categories.items():
        score = 0.0
        for keyword in keywords.get('primary', []):
            if keyword in name_lower:
                score += 5.0 * name_weight
            if desc_lower and keyword in desc_lower:
                score += 5.0 * desc_weight
        for keyword in keywords.get('secondary', []):
            if keyword in name_lower:
                score += 2.0 * name_weight
            if desc_lower and keyword in desc_lower:
                score += 2.0 * desc_weight
        for exclusion in keywords.get('exclusions', []):
            if exclusion in name_lower or (desc_lower and exclusion in desc_lower):
                score -= 10.0
        scores[category] = score

    if not scores or max(scores.values()) <= 0:
        return 'Other'

    best_category = max(scores, key=scores.get)
    if scores[best_category] < 2.0:
        return 'Other'
    return best_category


# ---------------------------------------------------------------------------
# SKILL.md Frontmatter Parser
# ---------------------------------------------------------------------------

def parse_skill_md(skill_md_path: Path) -> dict:
    """
    Parse SKILL.md and extract frontmatter fields.
    Returns a dict with: name, description, version, tags, raw_frontmatter
    """
    result = {
        "name": None,
        "description": None,
        "version": None,
        "tags": [],
        "raw_frontmatter": None,
    }
    try:
        content = skill_md_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return result

    fm_match = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
    if not fm_match:
        return result

    raw_fm = fm_match.group(1)
    result["raw_frontmatter"] = raw_fm

    name_match = re.search(r'^name:\s*([^\n]+)', raw_fm, re.MULTILINE)
    if name_match:
        result["name"] = name_match.group(1).strip().strip('"\'')

    version_match = re.search(r'^version:\s*([^\n]+)', raw_fm, re.MULTILINE)
    if version_match:
        result["version"] = version_match.group(1).strip().strip('"\'')

    # Description can be multiline (block scalar |- or >-)
    desc_match = re.search(r'^description:\s*(.+?)(?=\n\w|$)',
                           raw_fm, re.DOTALL | re.MULTILINE)
    if desc_match:
        raw_desc = desc_match.group(1)
        raw_desc = raw_desc.replace(
            '|-', '').replace('>-', '').replace('|', '').replace('>', '').strip()
        result["description"] = ' '.join(raw_desc.split())

    # Tags
    tags_match = re.search(r'^tags:\s*\[([^\]]*)\]', raw_fm, re.MULTILINE)
    if tags_match:
        tags_raw = tags_match.group(1)
        result["tags"] = [t.strip().strip('"\'')
                          for t in tags_raw.split(',') if t.strip()]
    else:
        # YAML list format
        tags_block = re.findall(r'^\s*-\s+(.+)$', raw_fm, re.MULTILINE)
        if tags_block:
            result["tags"] = [t.strip().strip('"\'') for t in tags_block]

    return result


# ---------------------------------------------------------------------------
# Blacklist
# ---------------------------------------------------------------------------

def load_blacklist(blacklist_path: Path) -> dict:
    """Load blacklist.yaml. Returns {authors: [], categories: [], keywords: []}."""
    default = {"authors": [], "categories": [], "keywords": []}
    if not blacklist_path.exists():
        return default
    try:
        with open(blacklist_path) as f:
            data = yaml.safe_load(f) or {}
        return {
            "authors": [a.lower() for a in (data.get("authors") or [])],
            "categories": [c.lower() for c in (data.get("categories") or [])],
            "keywords": [k.lower() for k in (data.get("keywords") or [])],
        }
    except Exception as e:
        print(f"  Warning: could not load blacklist.yaml: {e}")
        return default


def check_blacklist(blacklist: dict, author: str, category: str, skill_name: str, description: str) -> tuple[bool, str]:
    """
    Returns (is_blacklisted, reason).
    """
    author_l = (author or "").lower()
    category_l = (category or "").lower()
    combined = f"{skill_name or ''} {description or ''}".lower()

    if author_l in blacklist["authors"]:
        return True, f"blacklisted author: {author}"

    if category_l in blacklist["categories"]:
        return True, f"blacklisted category: {category}"

    for kw in blacklist["keywords"]:
        if kw in combined:
            return True, f"blacklisted keyword: {kw}"

    return False, ""


# ---------------------------------------------------------------------------
# Database Setup
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   VARCHAR PRIMARY KEY,
    value VARCHAR
);

CREATE TABLE IF NOT EXISTS skills (
    skill_path          VARCHAR PRIMARY KEY,  -- 'author/skill_name'
    skill_name          VARCHAR NOT NULL,
    skill_author        VARCHAR NOT NULL,
    skill_display_name  VARCHAR,              -- 'name' field from frontmatter
    skill_description   VARCHAR,
    skill_version       VARCHAR,
    skill_tags          VARCHAR,              -- JSON array string
    category            VARCHAR,
    date_added          TIMESTAMP,
    date_updated        TIMESTAMP,
    date_deleted        TIMESTAMP,
    is_deleted          BOOLEAN DEFAULT FALSE,
    is_blacklisted      BOOLEAN DEFAULT FALSE,
    blacklist_reason    VARCHAR DEFAULT '',
    scan_risk_level     VARCHAR DEFAULT 'UNKNOWN',
    scan_findings_count INTEGER DEFAULT 0,
    scan_date           TIMESTAMP,
    raw_frontmatter     VARCHAR,
    folder_size_bytes   BIGINT DEFAULT 0,
    file_count          INTEGER DEFAULT 0,
    script_count        INTEGER DEFAULT 0,
    md_count            INTEGER DEFAULT 0
);

-- Migrations for existing databases
ALTER TABLE skills ADD COLUMN IF NOT EXISTS folder_size_bytes BIGINT DEFAULT 0;
ALTER TABLE skills ADD COLUMN IF NOT EXISTS file_count        INTEGER DEFAULT 0;
ALTER TABLE skills ADD COLUMN IF NOT EXISTS script_count      INTEGER DEFAULT 0;
ALTER TABLE skills ADD COLUMN IF NOT EXISTS md_count          INTEGER DEFAULT 0;

CREATE TABLE IF NOT EXISTS scan_findings (
    id              INTEGER,
    skill_path      VARCHAR,
    rule_id         VARCHAR,
    severity        VARCHAR,
    category        VARCHAR,
    title           VARCHAR,
    description     VARCHAR,
    file            VARCHAR,
    line            INTEGER,
    evidence        VARCHAR,
    recommendation  VARCHAR,
    scanned_at      TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authors (
    username          VARCHAR PRIMARY KEY,  -- GitHub login (= skill_author)
    github_id         BIGINT,
    avatar_url        VARCHAR,
    name              VARCHAR,
    company           VARCHAR,
    blog              VARCHAR,
    location          VARCHAR,
    bio               VARCHAR,
    twitter_username  VARCHAR,
    public_repos      INTEGER,
    public_gists      INTEGER,
    followers         INTEGER,
    following         INTEGER,
    created_at        TIMESTAMP,
    updated_at        TIMESTAMP,           -- GitHub's updated_at
    fetched_at        TIMESTAMP,           -- when we fetched this
    http_status       INTEGER,             -- 200, 404, 403, etc.
    account_type      VARCHAR,             -- 'User', 'Organization', 'Bot'
    skill_count       INTEGER DEFAULT 0    -- denormalized for convenience
);
"""


def get_db(db_path: str) -> duckdb.DuckDBPyConnection:
    """Open DuckDB connection, install/load duck_tails, create schema."""
    con = duckdb.connect(db_path)
    con.execute("INSTALL duck_tails FROM community")
    con.execute("LOAD duck_tails")
    con.execute(SCHEMA_SQL)
    return con


def get_meta(con: duckdb.DuckDBPyConnection, key: str) -> Optional[str]:
    row = con.execute("SELECT value FROM meta WHERE key = ?", [key]).fetchone()
    return row[0] if row else None


def set_meta(con: duckdb.DuckDBPyConnection, key: str, value: str):
    con.execute("""
        INSERT INTO meta (key, value) VALUES (?, ?)
        ON CONFLICT (key) DO UPDATE SET value = excluded.value
    """, [key, value])


# ---------------------------------------------------------------------------
# Incremental Sync
# ---------------------------------------------------------------------------

def get_head_commit(con: duckdb.DuckDBPyConnection, repo_path: str) -> str:
    """Return the current HEAD commit hash."""
    row = con.execute(f"""
        SELECT commit_hash
        FROM git_log('{repo_path}')
        ORDER BY author_date DESC
        LIMIT 1
    """).fetchone()
    return row[0] if row else ""


def get_commits_since(con: duckdb.DuckDBPyConnection, repo_path: str, since_hash: Optional[str]) -> pd.DataFrame:
    """
    Return all commits newer than since_hash (exclusive).
    If since_hash is None, return all commits.
    """
    all_commits = con.execute(f"""
        SELECT commit_hash, author_name, author_date::TIMESTAMPTZ as author_date, message
        FROM git_log('{repo_path}')
        ORDER BY author_date ASC
    """).df()

    if not since_hash:
        return all_commits

    if since_hash not in all_commits["commit_hash"].values:
        # Can't find the saved hash (e.g., after a rebase) — process all
        print(
            f"  Warning: last commit hash {since_hash[:8]} not found in history, doing full sync")
        return all_commits

    idx = all_commits.index[all_commits["commit_hash"] == since_hash].tolist()[
        0]
    return all_commits.iloc[idx + 1:]


def get_head_skills(con: duckdb.DuckDBPyConnection, repo_path: str) -> set:
    """
    Return the set of 'author/skill_name' paths present in HEAD via git_tree.
    """
    rows = con.execute(f"""
        SELECT DISTINCT
            regexp_extract(file_path, 'skills/([^/]+/[^/]+)/SKILL\\.md', 1) as skill_path
        FROM git_tree('{repo_path}')
        WHERE file_path LIKE 'skills/%/SKILL.md'
          AND regexp_extract(file_path, 'skills/([^/]+/[^/]+)/SKILL\\.md', 1) != ''
    """).fetchall()
    return {r[0] for r in rows if r[0]}


def extract_touched_skills_from_commits(commits_df: pd.DataFrame) -> dict:
    """
    Parse commit messages to find skill paths that were added/updated/deleted.
    Returns {skill_path: {'operation': 'added'|'deleted', 'date': datetime, 'author': str}}
    """
    touched: dict = {}

    for _, row in commits_df.iterrows():
        message = row["message"]
        date = pd.to_datetime(row["author_date"])

        if message.startswith("skill:"):
            # Format: "skill: author/skill-name" or "skill: skill-name v1.0.0"
            # Try to extract author/skill or just skill-name
            match = re.search(r"skill:\s*([^\s]+)", message)
            if match:
                raw = match.group(1)
                # If it's already "author/skill", use it; otherwise we'll resolve later
                touched[raw] = {
                    "raw_slug": raw,
                    "operation": "added",
                    "date": date,
                    "git_author": row.get("author_name", ""),
                }

        elif message.startswith("delete:"):
            # Format: "delete: skills/author/skill-name"
            match = re.search(r"delete:\s*skills/([^/\s]+/[^/\s]+)", message)
            if match:
                skill_path = match.group(1)
                touched[skill_path] = {
                    "raw_slug": skill_path,
                    "operation": "deleted",
                    "date": date,
                    "git_author": row.get("author_name", ""),
                }

    return touched


def build_slug_lookup(head_skills: set) -> dict:
    """
    Build a reverse lookup dict: {skill_folder_name: author/skill_name}
    from the set of 'author/skill_name' paths in HEAD.
    When there are multiple authors with the same skill name, stores a list.
    """
    lookup: dict = {}
    for path in head_skills:
        parts = path.split("/", 1)
        if len(parts) == 2:
            skill_folder = parts[1]
            if skill_folder not in lookup:
                lookup[skill_folder] = path
            else:
                # Collision: store as list
                existing = lookup[skill_folder]
                if isinstance(existing, list):
                    existing.append(path)
                else:
                    lookup[skill_folder] = [existing, path]
    return lookup


def resolve_skill_path(slug: str, head_skills: set, slug_lookup: dict) -> Optional[str]:
    """
    Given a slug from a commit message (may be just skill-name or author/skill-name),
    find the actual 'author/skill_name' path using the pre-built HEAD lookup.
    """
    # Already a full author/skill path
    if "/" in slug:
        if slug in head_skills:
            return slug
        # Maybe only the skill part matched — extract the skill name and try
        skill_part = slug.split("/", 1)[1] if "/" in slug else slug
        result = slug_lookup.get(skill_part)
        if result and not isinstance(result, list):
            return result
        return None  # ambiguous or not found

    # Simple slug lookup
    result = slug_lookup.get(slug)
    if result is None:
        return None
    if isinstance(result, list):
        # Ambiguous: multiple authors — just pick the first for safety
        return result[0]
    return result


# ---------------------------------------------------------------------------
# Upsert skill into DB
# ---------------------------------------------------------------------------

def upsert_skill(
    con: duckdb.DuckDBPyConnection,
    repo_path: str,
    skill_path: str,       # 'author/skill_name'
    operation: str,        # 'added' | 'updated' | 'deleted'
    git_date: datetime,
    blacklist: dict,
    do_scan: bool = True,
):
    """
    Read SKILL.md, scan if needed, and upsert the skill row + findings.
    """
    parts = skill_path.split("/", 1)
    skill_author = parts[0] if len(parts) > 1 else "unknown"
    skill_name = parts[1] if len(parts) > 1 else parts[0]

    skill_dir = Path(repo_path) / "skills" / skill_path
    skill_md = skill_dir / "SKILL.md"

    # Check if already in DB
    existing = con.execute(
        "SELECT date_added, date_updated FROM skills WHERE skill_path = ?",
        [skill_path]
    ).fetchone()

    if operation == "deleted":
        if existing:
            con.execute("""
                UPDATE skills
                SET is_deleted = TRUE, date_deleted = ?
                WHERE skill_path = ?
            """, [git_date, skill_path])
        return

    # Parse frontmatter
    fm = parse_skill_md(skill_md) if skill_md.exists() else {}
    display_name = fm.get("name") or skill_name
    description = fm.get("description") or ""
    version = fm.get("version") or ""
    tags = json.dumps(fm.get("tags") or [])
    raw_fm = fm.get("raw_frontmatter") or ""

    # Categorize
    category = categorize_skill(skill_name, description)

    # Blacklist check
    is_blacklisted, blacklist_reason = check_blacklist(
        blacklist, skill_author, category, skill_name, description)

    # Security scan
    scan_risk = "UNKNOWN"
    scan_count = 0
    scan_date_val = None
    scan_findings_list = []

    if do_scan and skill_dir.exists():
        report = scan_skill_dir(skill_dir)
        scan_risk = report.get("overall_risk", "UNKNOWN")
        scan_count = report.get("total_findings", 0)
        scan_date_val = datetime.now(timezone.utc)
        scan_findings_list = report.get("findings", [])

    # Folder stats
    folder_stats = get_folder_stats(skill_dir) if skill_dir.exists() else {
        "folder_size_bytes": 0, "file_count": 0, "script_count": 0, "md_count": 0
    }

    # Upsert
    if existing:
        date_added = existing[0]
        con.execute("""
            UPDATE skills SET
                skill_name = ?,
                skill_author = ?,
                skill_display_name = ?,
                skill_description = ?,
                skill_version = ?,
                skill_tags = ?,
                category = ?,
                date_updated = ?,
                is_deleted = FALSE,
                date_deleted = NULL,
                is_blacklisted = ?,
                blacklist_reason = ?,
                scan_risk_level = ?,
                scan_findings_count = ?,
                scan_date = ?,
                raw_frontmatter = ?,
                folder_size_bytes = ?,
                file_count = ?,
                script_count = ?,
                md_count = ?
            WHERE skill_path = ?
        """, [
            skill_name, skill_author, display_name, description, version, tags,
            category, git_date, is_blacklisted, blacklist_reason,
            scan_risk, scan_count, scan_date_val, raw_fm,
            folder_stats["folder_size_bytes"], folder_stats["file_count"],
            folder_stats["script_count"], folder_stats["md_count"],
            skill_path,
        ])
    else:
        con.execute("""
            INSERT INTO skills (
                skill_path, skill_name, skill_author, skill_display_name,
                skill_description, skill_version, skill_tags, category,
                date_added, date_updated, is_deleted, is_blacklisted,
                blacklist_reason, scan_risk_level, scan_findings_count,
                scan_date, raw_frontmatter,
                folder_size_bytes, file_count, script_count, md_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, FALSE, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            skill_path, skill_name, skill_author, display_name,
            description, version, tags, category,
            git_date, is_blacklisted, blacklist_reason,
            scan_risk, scan_count, scan_date_val, raw_fm,
            folder_stats["folder_size_bytes"], folder_stats["file_count"],
            folder_stats["script_count"], folder_stats["md_count"],
        ])

    # Store detailed findings
    if scan_findings_list:
        # Remove old findings for this skill
        con.execute(
            "DELETE FROM scan_findings WHERE skill_path = ?", [skill_path])
        now = datetime.now(timezone.utc)
        for i, f in enumerate(scan_findings_list):
            con.execute("""
                INSERT INTO scan_findings (
                    id, skill_path, rule_id, severity, category, title,
                    description, file, line, evidence, recommendation, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                i + 1, skill_path, f["id"], f["severity"], f["category"],
                f["title"], f["description"], f["file"], f["line"],
                f["evidence"], f["recommendation"], now,
            ])


# ---------------------------------------------------------------------------
# Reconcile: mark deleted skills
# ---------------------------------------------------------------------------

def reconcile_deletions(con: duckdb.DuckDBPyConnection, head_skill_paths: set):
    """
    Mark any skills in DB (not already deleted) that are absent from HEAD as deleted.
    """
    db_active = con.execute(
        "SELECT skill_path FROM skills WHERE is_deleted = FALSE"
    ).fetchall()
    db_active_paths = {r[0] for r in db_active}

    removed = db_active_paths - head_skill_paths
    now = datetime.now(timezone.utc)
    for sp in removed:
        con.execute("""
            UPDATE skills
            SET is_deleted = TRUE, date_deleted = ?
            WHERE skill_path = ?
        """, [now, sp])

    return len(removed)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def print_stats(con: duckdb.DuckDBPyConnection):
    total = con.execute(
        "SELECT COUNT(*) FROM skills WHERE is_deleted = FALSE").fetchone()[0]
    deleted = con.execute(
        "SELECT COUNT(*) FROM skills WHERE is_deleted = TRUE").fetchone()[0]
    blacklisted = con.execute(
        "SELECT COUNT(*) FROM skills WHERE is_blacklisted = TRUE AND is_deleted = FALSE").fetchone()[0]
    findings = con.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0]
    last_run = get_meta(con, "last_run") or "never"
    last_commit = get_meta(con, "last_commit_hash") or "none"

    print(f"\n{'='*60}")
    print("  OPENCLAW SKILLS CATALOG — STATS")
    print(f"{'='*60}")
    print(f"  Active skills    : {total:,}")
    print(f"  Deleted skills   : {deleted:,}")
    print(f"  Blacklisted      : {blacklisted:,}")
    print(f"  Scan findings    : {findings:,}")
    print(f"  Last run         : {last_run}")
    print(
        f"  Last commit hash : {last_commit[:12] if last_commit != 'none' else 'none'}")
    print()

    print("  Risk levels (active, non-blacklisted):")
    rows = con.execute("""
        SELECT scan_risk_level, COUNT(*) as cnt
        FROM skills
        WHERE is_deleted = FALSE AND is_blacklisted = FALSE
        GROUP BY scan_risk_level
        ORDER BY cnt DESC
    """).fetchall()
    for r in rows:
        print(f"    {r[0]:<12} : {r[1]:,}")

    print()
    print("  Top categories:")
    rows = con.execute("""
        SELECT category, COUNT(*) as cnt
        FROM skills
        WHERE is_deleted = FALSE AND is_blacklisted = FALSE
        GROUP BY category
        ORDER BY cnt DESC
        LIMIT 15
    """).fetchall()
    for r in rows:
        print(f"    {r[0]:<35} : {r[1]:,}")
    print()


# ---------------------------------------------------------------------------
# Main Entry
# ---------------------------------------------------------------------------

def enrich_authors(con: duckdb.DuckDBPyConnection, github_token=None, batch_size=500):
    """Enrich author profiles from the GitHub REST API.

    Only authors with 2+ active skills who haven't been fetched yet are queried.
    Results (including errors like 404) are cached so they won't be re-fetched.
    """
    print("\n" + "=" * 60)
    print("  AUTHOR ENRICHMENT")
    print("=" * 60)

    # Update skill_count for all known authors first
    con.execute("""
        INSERT INTO authors (username, skill_count)
            SELECT skill_author, COUNT(*) AS cnt
            FROM skills
            WHERE NOT is_deleted AND NOT is_blacklisted
            GROUP BY skill_author
            HAVING cnt >= 2
        ON CONFLICT (username) DO UPDATE SET skill_count = EXCLUDED.skill_count
    """)

    # Find authors needing enrichment (never fetched)
    rows = con.execute("""
        SELECT a.username
        FROM authors a
        WHERE a.fetched_at IS NULL
        ORDER BY a.skill_count DESC
        LIMIT ?
    """, [batch_size]).fetchall()

    to_fetch = [r[0] for r in rows]
    total = len(to_fetch)
    print(f"  Authors with 2+ skills needing enrichment: {total}")

    if total == 0:
        print("  Nothing to enrich.")
        return

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "openclaw-skills-catalog",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    fetched = 0
    errors = 0

    for i, username in enumerate(to_fetch, 1):
        url = f"https://api.github.com/users/{urllib.request.quote(username, safe='')}"
        req = urllib.request.Request(url, headers=headers)

        http_status = None
        data = {}

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                http_status = resp.status
                data = json.loads(resp.read().decode())

                # Check rate limit
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining is not None and int(remaining) < 100:
                    print(f"  Rate limit low ({remaining} remaining) — stopping early.")
                    _upsert_author(con, username, http_status, data)
                    fetched += 1
                    break

        except urllib.error.HTTPError as e:
            http_status = e.code
            try:
                data = json.loads(e.read().decode())
            except Exception:
                data = {}
            if http_status in (403, 429):
                print(f"  Rate limited (HTTP {http_status}) — stopping early.")
                break
        except Exception as e:
            print(f"  Error fetching {username}: {e}")
            http_status = 0
            errors += 1

        _upsert_author(con, username, http_status, data)
        fetched += 1

        if i % 50 == 0 or i == total:
            print(f"  [{i}/{total}] fetched (last: {username})")

        time.sleep(0.8)

    print(f"\n  Enrichment complete: {fetched} fetched, {errors} errors")


def _upsert_author(con, username, http_status, data):
    """Insert or update an author row from GitHub API response data."""
    now = datetime.now(timezone.utc).isoformat()

    def _ts(val):
        """Parse GitHub ISO timestamp or return None."""
        if not val:
            return None
        return val.replace("Z", "+00:00")

    con.execute("""
        INSERT INTO authors (
            username, github_id, avatar_url, name, company, blog,
            location, bio, twitter_username, public_repos, public_gists,
            followers, following, created_at, updated_at,
            fetched_at, http_status, account_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::TIMESTAMP, ?::TIMESTAMP, ?::TIMESTAMP, ?, ?)
        ON CONFLICT (username) DO UPDATE SET
            github_id        = EXCLUDED.github_id,
            avatar_url       = EXCLUDED.avatar_url,
            name             = EXCLUDED.name,
            company          = EXCLUDED.company,
            blog             = EXCLUDED.blog,
            location         = EXCLUDED.location,
            bio              = EXCLUDED.bio,
            twitter_username = EXCLUDED.twitter_username,
            public_repos     = EXCLUDED.public_repos,
            public_gists     = EXCLUDED.public_gists,
            followers        = EXCLUDED.followers,
            following        = EXCLUDED.following,
            created_at       = EXCLUDED.created_at,
            updated_at       = EXCLUDED.updated_at,
            fetched_at       = EXCLUDED.fetched_at,
            http_status      = EXCLUDED.http_status,
            account_type     = EXCLUDED.account_type
    """, [
        username,
        data.get("id"),
        data.get("avatar_url"),
        data.get("name"),
        data.get("company"),
        data.get("blog"),
        data.get("location"),
        data.get("bio"),
        data.get("twitter_username"),
        data.get("public_repos"),
        data.get("public_gists"),
        data.get("followers"),
        data.get("following"),
        _ts(data.get("created_at")),
        _ts(data.get("updated_at")),
        now,
        http_status,
        data.get("type"),
    ])


def export_parquet(con: duckdb.DuckDBPyConnection, out_dir: str):
    """Export skills and findings tables to Parquet files for the dashboard UI."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    skills_path = out / "skills.parquet"
    findings_path = out / "findings.parquet"

    print(f"\nExporting Parquet files to {out}...")

    con.execute(f"""
        COPY (
            SELECT
                skill_path,
                skill_name,
                skill_author,
                skill_display_name,
                skill_description,
                skill_version,
                skill_tags,
                category,
                date_added::VARCHAR   AS date_added,
                date_updated::VARCHAR AS date_updated,
                date_deleted::VARCHAR AS date_deleted,
                is_deleted,
                is_blacklisted,
                blacklist_reason,
                scan_risk_level,
                scan_findings_count,
                scan_date::VARCHAR    AS scan_date,
                folder_size_bytes,
                file_count,
                script_count,
                md_count
            FROM skills
        ) TO '{skills_path}' (FORMAT PARQUET, COMPRESSION ZSTD)
    """)
    size_kb = os.path.getsize(skills_path) // 1024
    print(f"  skills.parquet  : {size_kb} KB")

    con.execute(f"""
        COPY (
            SELECT
                id,
                skill_path,
                rule_id,
                severity,
                category          AS finding_category,
                title,
                description,
                file,
                line,
                evidence,
                recommendation,
                scanned_at::VARCHAR AS scanned_at
            FROM scan_findings
        ) TO '{findings_path}' (FORMAT PARQUET, COMPRESSION ZSTD)
    """)
    size_kb = os.path.getsize(findings_path) // 1024
    print(f"  findings.parquet: {size_kb} KB")

    # Authors parquet (only if the table has data)
    author_count = con.execute(
        "SELECT COUNT(*) FROM authors WHERE http_status = 200"
    ).fetchone()[0]
    if author_count > 0:
        authors_path = out / "authors.parquet"
        con.execute(f"""
            COPY (
                SELECT * FROM authors
                WHERE http_status = 200
                ORDER BY followers DESC
            ) TO '{authors_path}' (FORMAT PARQUET, COMPRESSION ZSTD)
        """)
        size_kb = os.path.getsize(authors_path) // 1024
        print(f"  authors.parquet : {size_kb} KB ({author_count} authors)")


def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw Skills Catalog Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run skills_catalog.py --repo-path /skills
  uv run skills_catalog.py --repo-path /skills --db /tmp/catalog.duckdb
  uv run skills_catalog.py --repo-path /skills --full-rescan
  uv run skills_catalog.py --repo-path /skills --stats
        """,
    )
    parser.add_argument("--repo-path", default="/skills",
                        help="Path to skills git repository")
    parser.add_argument(
        "--db",
        default="/workspaces/openclaw-skills/skills_catalog.duckdb",
        help="Path to DuckDB catalog file",
    )
    parser.add_argument(
        "--blacklist",
        default="/workspaces/openclaw-skills/blacklist.yaml",
        help="Path to blacklist.yaml",
    )
    parser.add_argument(
        "--full-rescan",
        action="store_true",
        help="Re-scan all active skills (ignore last commit checkpoint)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print catalog stats and exit",
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip security scanning (faster, metadata-only update)",
    )
    parser.add_argument(
        "--export-dir",
        default="/workspaces/openclaw-skills/skills-dashboard/public",
        help="Directory to write skills.parquet and findings.parquet for the dashboard UI (set to '' to skip)",
    )
    parser.add_argument(
        "--enrich-authors",
        action="store_true",
        help="Enable GitHub author enrichment (default: off unless token provided)",
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN", ""),
        help="GitHub PAT for API auth (or env: GITHUB_TOKEN)",
    )
    parser.add_argument(
        "--author-batch-size",
        type=int,
        default=500,
        help="Max authors to enrich per run (default: 500)",
    )
    args = parser.parse_args()

    repo_path = args.repo_path
    if not Path(repo_path).exists():
        print(f"Error: repo path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print("  OPENCLAW SKILLS CATALOG BUILDER")
    print("=" * 60)
    print(f"  Repo     : {repo_path}")
    print(f"  DB       : {args.db}")
    print(f"  Blacklist: {args.blacklist}")
    print()

    print("Connecting to DuckDB and loading duck_tails...")
    con = get_db(args.db)

    if args.stats:
        print_stats(con)
        con.close()
        return

    # Load blacklist
    blacklist = load_blacklist(Path(args.blacklist))
    print(
        f"Blacklist loaded: {len(blacklist['authors'])} authors, {len(blacklist['categories'])} categories, {len(blacklist['keywords'])} keywords")

    # Get HEAD commit
    print("Reading HEAD commit hash...")
    head_commit = get_head_commit(con, repo_path)
    if not head_commit:
        print("Error: could not read HEAD commit from repo", file=sys.stderr)
        sys.exit(1)
    print(f"  HEAD: {head_commit[:12]}")

    last_commit = None if args.full_rescan else get_meta(
        con, "last_commit_hash")
    if last_commit:
        print(f"  Last processed: {last_commit[:12]}")
    else:
        print("  First run or full rescan — processing all commits")

    # Get new commits
    print("Fetching commits...")
    new_commits = get_commits_since(con, repo_path, last_commit)
    print(f"  {len(new_commits)} new commits to process")

    if len(new_commits) == 0 and not args.full_rescan:
        print("\nNothing new to process.")
        print_stats(con)
        should_enrich = args.enrich_authors or bool(args.github_token)
        if should_enrich:
            enrich_authors(
                con,
                github_token=args.github_token or None,
                batch_size=args.author_batch_size,
            )
        if args.export_dir:
            export_parquet(con, args.export_dir)
        con.close()
        return

    # Parse touched skills from commit messages
    print("Parsing touched skills from commit messages...")
    touched = extract_touched_skills_from_commits(new_commits)
    print(f"  {len(touched)} skills mentioned in commits")

    # Get full HEAD skill set for reconciliation
    print("Reading HEAD skill tree...")
    head_skills = get_head_skills(con, repo_path)
    print(f"  {len(head_skills)} skills in HEAD")

    # Build fast slug lookup from HEAD skills
    slug_lookup = build_slug_lookup(head_skills)

    # If full rescan: process all skills in HEAD
    if args.full_rescan:
        print("Full rescan: processing all HEAD skills...")
        to_process = {sp: {"operation": "added", "date": datetime.now(
            timezone.utc)} for sp in head_skills}
    else:
        # Resolve slugs from commit messages to actual author/skill paths
        to_process: dict = {}
        for slug, info in touched.items():
            if info["operation"] == "deleted":
                # For deletes, trust the commit message path
                to_process[slug] = info
            else:
                resolved = resolve_skill_path(slug, head_skills, slug_lookup)
                if resolved:
                    to_process[resolved] = info
                else:
                    print(
                        f"  Warn: could not resolve skill slug '{slug}', skipping")

    do_scan = not args.no_scan
    added_count = 0
    updated_count = 0
    deleted_count = 0
    error_count = 0

    total = len(to_process)
    print(
        f"\nProcessing {total} skills (scan={'yes' if do_scan else 'no'})...")

    for i, (skill_path, info) in enumerate(to_process.items(), 1):
        op = info.get("operation", "added")
        git_date = info.get("date", datetime.now(timezone.utc))

        # Check if existing to decide added vs updated
        existing = con.execute(
            "SELECT skill_path FROM skills WHERE skill_path = ? AND is_deleted = FALSE",
            [skill_path]
        ).fetchone()

        if op == "deleted":
            display_op = "DEL"
            deleted_count += 1
        elif existing:
            display_op = "UPD"
            updated_count += 1
            op = "updated"
        else:
            display_op = "ADD"
            added_count += 1

        if i % 100 == 0 or i == total:
            print(f"  [{i}/{total}] {display_op} {skill_path}")
        elif i % 25 == 0:
            print(f"  [{i}/{total}]...")

        try:
            upsert_skill(con, repo_path, skill_path, op,
                         git_date, blacklist, do_scan=do_scan)
        except Exception as e:
            print(f"  Error processing {skill_path}: {e}")
            error_count += 1

    # Reconcile deletions: anything in DB that's not in HEAD
    if not args.full_rescan:
        print("\nReconciling deletions against HEAD tree...")
        reconciled = reconcile_deletions(con, head_skills)
        if reconciled:
            print(
                f"  Marked {reconciled} skills as deleted (no longer in HEAD)")
            deleted_count += reconciled

    # Update meta
    set_meta(con, "last_commit_hash", head_commit)
    set_meta(con, "last_run", datetime.now(timezone.utc).isoformat())

    print(f"\nDone:")
    print(f"  Added:   {added_count}")
    print(f"  Updated: {updated_count}")
    print(f"  Deleted: {deleted_count}")
    if error_count:
        print(f"  Errors:  {error_count}")

    print_stats(con)

    # Author enrichment — runs if flag set or token provided
    should_enrich = args.enrich_authors or bool(args.github_token)
    if should_enrich:
        enrich_authors(
            con,
            github_token=args.github_token or None,
            batch_size=args.author_batch_size,
        )

    if args.export_dir:
        export_parquet(con, args.export_dir)

    con.close()


if __name__ == "__main__":
    main()
