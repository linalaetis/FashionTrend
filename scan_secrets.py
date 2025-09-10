#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, argparse, subprocess, math, sys
from pathlib import Path
from typing import List
from collections import Counter

VERSION_TAG = "Scanner v2.1 (scan + summary)"

# --- Params défaut ---
IGNORE_DIRS = {".git", ".venv", "venv", "env", ".env", "build", "dist",
               "node_modules", "__pycache__", ".ipynb_checkpoints",
               ".mypy_cache", ".pytest_cache", ".ruff_cache"}
SCAN_EXTS = {".py", ".ipynb", ".env", ".json", ".yml", ".yaml",
             ".txt", ".cfg", ".ini", ".toml", ".sh", ".ps1", ".md"}

SECRET_REGEXES = {
    "AWS Access Key ID": re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack token": re.compile(r"xox[abp]-[0-9A-Za-z\-]{10,}"),
    "Private key header": re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    "Generic API Key/Token": re.compile(r"(?i)(api[_-]?key|apikey|x-api-key|secret|token|access[_-]?token)\s*[:=]\s*['\"][0-9A-Za-z_\-]{16,}['\"]"),
    "Bearer token": re.compile(r"(?i)bearer\s+[0-9A-Za-z\-_\.=]{20,}"),
    "Password assignment": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"].+['\"]"),
    "JWT token": re.compile(r"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
}

DEFAULT_ALLOWLIST_REGEXES = [
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",  # UUID
    r"\b[0-9a-fA-F]{32}\b",   # MD5 / UUID compact (ignoré par défaut)
    r"\b[0-9a-fA-F]{40}\b",   # SHA-1
    r"\b[0-9a-fA-F]{64}\b",   # SHA-256
    r"^iVBORw0KGgo", r"^/9j/", r"^R0lGOD",  # base64 images
    r"data:image/(?:png|jpeg|jpg|gif);base64,",
    r"(?i)\bhttps?://[^\s\"']+",           # URLs
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",  # emails
]

def to_regex_list(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p) for p in patterns]

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    c = Counter(s); n = len(s)
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in c.values())

def looks_base64(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]{24,}", s))

def high_entropy_candidates(line: str, min_entropy: float):
    hits = []
    for token in re.findall(r"[A-Za-z0-9_\-\.=]{24,}", line):
        if shannon_entropy(token) >= min_entropy or looks_base64(token):
            hits.append(("High-entropy string", token[:80] + ("..." if len(token) > 80 else "")))
    return hits

def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(2048)
    except Exception:
        return True

def any_allowlisted(s: str, allowlist_res: List[re.Pattern], ignore_hashes: bool) -> bool:
    for rgx in allowlist_res:
        if rgx.search(s):
            if not ignore_hashes and rgx.pattern in (r"\b[0-9a-fA-F]{32}\b", r"\b[0-9a-fA-F]{40}\b", r"\b[0-9a-fA-F]{64}\b"):
                continue
            return True
    return False

def load_secretignore() -> List[str]:
    p = Path(".secretignore")
    if p.exists():
        try:
            return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
        except Exception:
            return []
    return []

def scan_text(content: str, where: str, findings: list, allowlist_res: List[re.Pattern], min_entropy: float, ignore_hashes: bool):
    for i, line in enumerate(content.splitlines(), 1):
        for name, rgx in SECRET_REGEXES.items():
            for m in rgx.finditer(line):
                snippet = m.group(0)
                if not any_allowlisted(snippet, allowlist_res, ignore_hashes):
                    findings.append((where, i, name, snippet))
        for name, snippet in high_entropy_candidates(line, min_entropy):
            if not any_allowlisted(snippet, allowlist_res, ignore_hashes):
                findings.append((where, i, name, snippet))

def scan_notebook(path: Path, findings: list, allowlist_res: List[re.Pattern], min_entropy: float, ignore_outputs: bool, ignore_hashes: bool):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    for cell in data.get("cells", []):
        if cell.get("cell_type") == "code":
            src = "".join(cell.get("source", []))
            scan_text(src, f"{path}::code", findings, allowlist_res, min_entropy, ignore_hashes)
            if ignore_outputs:
                continue
            for output in cell.get("outputs", []):
                for key in ("text", "data"):
                    if key in output:
                        out = output[key]
                        if isinstance(out, dict):
                            for v in out.values():
                                if isinstance(v, list):
                                    scan_text("".join(v), f"{path}::output", findings, allowlist_res, min_entropy, ignore_hashes)
                                elif isinstance(v, str):
                                    scan_text(v, f"{path}::output", findings, allowlist_res, min_entropy, ignore_hashes)
                        elif isinstance(out, list):
                            scan_text("".join(out), f"{path}::output", findings, allowlist_res, min_entropy, ignore_hashes)
                        elif isinstance(out, str):
                            scan_text(out, f"{path}::output", findings, allowlist_res, min_entropy, ignore_hashes)

def walk_repo(root: Path, ex_dirs: List[str]):
    ex_set = IGNORE_DIRS.union(set(ex_dirs))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ex_set and not d.startswith(".git")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in SCAN_EXTS or p.name.lower().endswith(".env"):
                yield p

def git_present() -> bool:
    return (Path(".git").exists() and Path(".git").is_dir())

def scan_git_history(paths: List[Path], findings: list, allowlist_res: List[re.Pattern], min_entropy: float, ignore_hashes: bool):
    if not git_present():
        return
    for p in paths:
        try:
            proc = subprocess.run(
                ["git", "log", "-p", "--all", "--", str(p)],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False
            )
            if proc.stdout:
                scan_text(proc.stdout, f"{p}::GIT_HISTORY", findings, allowlist_res, min_entropy, ignore_hashes)
        except Exception:
            pass

def write_report(findings, out_path: Path):
    header = "# Rapport de scan de secrets (filtré)\n\n"
    if not findings:
        out_path.write_text(header + "✅ Aucun secret détecté.\n", encoding="utf-8")
        return 0
    with out_path.open("w", encoding="utf-8") as f:
        f.write(header)
        f.write(f"⚠️ {len(findings)} occurrences suspectes après filtrage.\n\n")
        f.write("| Fichier | Ligne | Type | Extrait |\n|---|---:|---|---|\n")
        for where, line, name, snippet in findings:
            f.write(f"| {where} | {line} | {name} | `{str(snippet).replace('|','\\|')}` |\n")
    return len(findings)

def summarize_report(report_path: Path):
    if not report_path.exists():
        print(f"Résumé: rapport introuvable: {report_path}")
        return
    counts = Counter()
    total = 0
    with report_path.open(encoding="utf-8") as f:
        for line in f:
            if line.startswith("| "):
                cols = [c.strip() for c in line.strip().split("|")]
                if len(cols) >= 5 and cols[1] != "Fichier":
                    type_col = cols[3]
                    counts[type_col] += 1
                    total += 1
    if total == 0:
        print("Résumé: ✅ Aucun secret détecté (ou tableau vide).")
        return
    print("\n=== Résumé par type ===")
    for k, v in counts.most_common():
        print(f"- {k}: {v}")
    print(f"Total: {total}\n")

def main():
    print(VERSION_TAG)
    ap = argparse.ArgumentParser(description="Scan de secrets (fichiers, notebooks, historique Git) + résumé du rapport.")
    ap.add_argument("--history", action="store_true", help="Scanner aussi l'historique Git (plus lent).")
    ap.add_argument("--out", default="secrets_report.md", help="Fichier de rapport Markdown.")
    ap.add_argument("--root", default=".", help="Racine du projet à scanner.")
    ap.add_argument("--skip-outputs", action="store_true", help="Ignorer les sorties des notebooks (réduit le bruit).")
    ap.add_argument("--min-entropy", type=float, default=4.5, help="Seuil d'entropie pour alerter (défaut=4.5).")
    ap.add_argument("--allow-pattern", action="append", default=[], help="Regex à ignorer (peut être passée plusieurs fois).")
    ap.add_argument("--exclude", action="append", default=[], help="Dossiers supplémentaires à exclure (peut être passée plusieurs fois).")
    ap.add_argument("--no-ignore-hash", action="store_true", help="Ne pas ignorer les chaînes hex de 32/40/64 chars.")
    ap.add_argument("--summary-only", action="store_true", help="Ne pas scanner: seulement résumer le fichier --out existant.")
    args = ap.parse_args()

    report_path = Path(args.out).resolve()

    if args.summary_only:
        summarize_report(report_path)
        return

    # Allowlist combinée
    allow_patterns = list(DEFAULT_ALLOWLIST_REGEXES)
    allow_patterns.extend(load_secretignore())
    allow_patterns.extend(args.allow_pattern or [])
    allowlist_res = to_regex_list(allow_patterns)

    root = Path(args.root).resolve()
    findings = []
    paths = list(walk_repo(root, args.exclude))

    for p in paths:
        if p.suffix == ".ipynb":
            scan_notebook(p, findings, allowlist_res, args.min_entropy, args.skip_outputs, not args.no_ignore_hash)
        else:
            if is_binary(p): 
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            scan_text(text, str(p), findings, allowlist_res, args.min_entropy, not args.no_ignore_hash)

    if args.history:
        scan_git_history(paths, findings, allowlist_res, args.min_entropy, not args.no_ignore_hash)

    n = write_report(findings, report_path)

    if n == 0:
        print(f"OK: Aucun secret détecté. Rapport: {report_path}")
        return
    else:
        print(f"ATTENTION: {n} occurrences suspectes après filtrage. Rapport: {report_path}")

    # Afficher le résumé tout de suite
    summarize_report(report_path)

    # Code de sortie non nul pour CI si des occurrences existent
    raise SystemExit(2)

if __name__ == "__main__":
    main()
