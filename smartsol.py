#!/usr/bin/env python3
"""
Smartsol — AI-powered smart contract audit in one command.

Scans Solidity code with Slither, then uses an LLM to strip false positives
and rank the REAL findings by severity with exploit path + fix suggestions.

Usage:
    smartsol scan <dir_or_sol> [--json] [--out FILE] [--model MODEL]
    smartsol version

Built by laolaoqi. MIT licensed. Run at your own risk.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"

DEFAULT_MODEL = "deepseek-chat"
DEEPSEEK_API = os.environ.get(
    "SMARTSOL_API_URL", "https://api.deepseek.com/chat/completions"
)
API_KEY = os.environ.get("SMARTSOL_API_KEY", os.environ.get("DEEPSEEK_API_KEY", ""))
# WARNING: a hard-coded key here would be rejected by GitHub secret scanning.
# Set SMARTSOL_API_KEY (or DEEPSEEK_API_KEY) in your environment instead.

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


# --------------------------------------------------------------------------- #
# Slither layer
# --------------------------------------------------------------------------- #
def _has_foundry(target: str) -> bool:
    """True if target dir looks like a Foundry project (has foundry.toml)."""
    base = target if os.path.isdir(target) else os.path.dirname(target) or "."
    for up in (base, os.path.dirname(base.rstrip("/"))):
        if os.path.exists(os.path.join(up, "foundry.toml")):
            return True
    return False


def forge_build(target: str):
    """Run forge build inside a foundry project dir (best-effort)."""
    base = target if os.path.isdir(target) else os.path.dirname(target) or "."
    try:
        subprocess.run(
            ["forge", "build", "--force"], cwd=base, capture_output=True, text=True,
            timeout=300,
        )
    except Exception as e:
        print(f"! forge build skipped: {e}", file=sys.stderr)


def run_slither(target: str) -> list:
    """Run Slither (auto-compile Foundry first, then scan) and return findings."""
    # 1) If a Foundry project, ensure it's compiled so slither can consume it.
    if os.path.isdir(target) and _has_foundry(target):
        forge_build(target)

    cmd = ["slither", target, "--json", "-"]
    # Force foundry framework when target is a foundry project dir
    if os.path.isdir(target) and _has_foundry(target):
        cmd += ["--compile-force-framework", "foundry"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            env={**os.environ, "CI": "true"},
        )
        out = proc.stdout or ""
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            # slither prints findings on stderr in non-json mode too
            return _parse_slither_text(proc.stderr or out or "")
        res = data.get("results", {})
        detectors = res.get("detectors", [])
        parsed = []
        for d in detectors:
            parsed.append({
                "check": d.get("check", "unknown"),
                "impact": d.get("impact", "Informational"),
                "confidence": d.get("confidence", "Unknown"),
                "description": d.get("description", ""),
                "elements": [
                    {
                        "source_mapping": e.get("source_mapping", {}),
                        "type": e.get("type", ""),
                        "name": e.get("name", ""),
                    }
                    for e in d.get("elements", [])
                ],
            })
        return parsed
    except FileNotFoundError:
        print("! slither not installed. pip install slither-analyzer", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print("! slither timed out (600s)", file=sys.stderr)
        return []


def _parse_slither_text(text: str) -> list:
    """Fallback parser if slither returns plain text (old versions)."""
    findings = []
    cur = None
    for line in text.splitlines():
        if line.startswith("Contract") or " (" in line and "Impact" not in line:
            continue
        if line.strip() and cur is None and ("Impact:" in line or "###" in line):
            cur = {"raw": line.strip()}
        elif cur is not None:
            if line.strip() == "":
                if cur.get("raw"):
                    findings.append(cur)
                cur = None
            else:
                cur.setdefault("desc", "").append(line.strip())
    return findings


# --------------------------------------------------------------------------- #
# LLM layer
# --------------------------------------------------------------------------- #
def _llm(system: str, user: str, model: str) -> str:
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 4000,
    }).encode()
    req = urllib.request.Request(
        DEEPSEEK_API, data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"! LLM call failed: {e}", file=sys.stderr)
        return ""


def triage_findings(sol_source: str, findings: list, model: str) -> list:
    """
    Send Slither findings + relevant source to the LLM.
    Returns a filtered/ranked list: [{severity, title, location, exploit, fix, fp}]
    """
    if not findings:
        return []
    # Build compact source context: first N lines around flagged elements
    lines = sol_source.split("\n")
    flagged_lines = set()
    for f in findings:
        for e in f.get("elements", []):
            sm = e.get("source_mapping", {})
            start = sm.get("lines", [])
            if start:
                flagged_lines.update(list(range(max(0, start[0] - 3), start[0] + 6)))
    context_lines = sorted(flagged_lines)
    src_excerpt = "\n".join(f"{i+1}: {lines[i]}" for i in context_lines if i < len(lines))
    src_excerpt = src_excerpt[:12000]  # keep prompt bounded

    # Compact slither summary
    det_summary = []
    for f in findings[:80]:
        det_summary.append(
            f"[{f['impact']}/{f['confidence']}] {f['check']}: {f['description'][:160]}"
        )
    det_text = "\n".join(det_summary)

    system = (
        "You are a world-class smart contract security auditor. "
        "You are given Slither static-analysis findings plus a source excerpt. "
        "Your job: separate TRUE vulnerabilities from FALSE POSITIVES, and rank "
        "the real ones by severity. Respond ONLY with a JSON array. No prose.\n"
        "Each item schema:\n"
        '{"severity":"Critical|High|Medium|Low","title":"...","location":"File:line",'
        '"exploit":"concise attack path","fix":"concrete remediation",'
        '"false_positive":true/false}\n'
        "Rules: uncontrolled reentrancy on eth/erc777 = Critical. "
        "unchecked arithmetic only if overflow reachable = High. "
        "missing zero-address check = Low unless it gates funds. "
        "If a finding is not exploitable in context, mark false_positive:true."
    )
    user = (
        f"### Slither findings\n{det_text}\n\n"
        f"### Source excerpt (line: code)\n```solidity\n{src_excerpt}\n```\n\n"
        "Return JSON array of triaged findings (include false positives too, marked)."
    )
    raw = _llm(system, user, model)
    return _parse_llm_json(raw)


def _parse_llm_json(raw: str) -> list:
    """Robustly extract a JSON array from the LLM reply."""
    if not raw:
        return []
    # strip code fences
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1]
        if s.startswith("json"):
            s = s[4:]
    # find first [ and last ]
    a, b = s.find("["), s.rfind("]")
    if a == -1 or b == -1 or b <= a:
        return []
    try:
        arr = json.loads(s[a:b + 1])
        return [x for x in arr if isinstance(x, dict)] if isinstance(arr, list) else []
    except json.JSONDecodeError:
        return []


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def build_report(findings: list, sol_path: str, model: str) -> str:
    triaged = [f for f in findings if isinstance(f, dict)]
    real = [f for f in triaged if not f.get("false_positive")]
    real.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "Low"), 1), reverse=True)
    fps = [f for f in triaged if f.get("false_positive")]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    lines.append(f"# 🔒 Smartsol Audit Report")
    lines.append(f"")
    lines.append(f"**Target:** `{sol_path}`  ")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Model:** {DEFAULT_MODEL if model == DEFAULT_MODEL else model}  ")
    lines.append(f"**Findings:** {len(real)} real · {len(fps)} false positives filtered")
    lines.append(f"")
    lines.append(f"---")

    if not real:
        lines.append("")
        lines.append("✅ **No exploitable vulnerabilities found.**")
        if fps:
            lines.append(f"({len(fps)} Slither hits triaged as false positives by AI)")
        lines.append("")
        return "\n".join(lines)

    sev_badge = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}
    for f in real:
        sev = f.get("severity", "Low")
        badge = sev_badge.get(sev, "⚪")
        lines.append("")
        lines.append(f"## {badge} {sev} — {f.get('title','Untitled')}")
        lines.append(f"")
        if f.get("location"):
            lines.append(f"**Location:** `{f['location']}`")
            lines.append("")
        if f.get("exploit"):
            lines.append(f"**Exploit path:** {f['exploit']}")
            lines.append("")
        if f.get("fix"):
            lines.append(f"**Fix:** {f['fix']}")
            lines.append("")
        lines.append("---")
    return "\n".join(lines)


def build_json(findings: list) -> str:
    triaged = [f for f in findings if isinstance(f, dict) and not f.get("false_positive")]
    return json.dumps({"findings": triaged}, indent=2)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(prog="smartsol", description="AI smart-contract auditor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="scan a .sol file or directory")
    scan.add_argument("target")
    scan.add_argument("--json", action="store_true", help="emit JSON findings")
    scan.add_argument("--out", help="write report to this file")
    scan.add_argument("--model", default=DEFAULT_MODEL)
    scan.add_argument("--no-slither", action="store_true", help="skip slither run (dry)")
    sub.add_parser("version", help="print version")
    args = ap.parse_args()

    if args.cmd == "version":
        print(f"smartsol {__version__}")
        return

    target = args.target
    if not os.path.exists(target):
        print(f"! path not found: {target}", file=sys.stderr); sys.exit(2)

    # Gather sol source (main file if single, else concat key files)
    if target.endswith(".sol"):
        sol_path = os.path.basename(target)
        with open(target) as f:
            source = f.read()
    else:
        sol_path = "contracts/"
        sols = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ("node_modules", "lib", "test", "tests", "mock", "mocks")]
            for fn in files:
                if fn.endswith(".sol"):
                    sols.append(os.path.join(root, fn))
        source = "\n\n// --- file ---\n".join(open(f).read() for f in sols[:25])
        if not sols:
            print("! no .sol files found", file=sys.stderr); sys.exit(3)

    print(f"▶ Slither scanning {target} ...")
    findings = [] if args.no_slither else run_slither(target)
    print(f"  Slither: {len(findings)} raw findings")

    if not findings:
        print("  No raw findings — nothing to triage.")
        report = build_report([], sol_path, args.model)
    else:
        print(f"▶ AI triage with {args.model} ...")
        triaged = triage_findings(source, findings, args.model)
        report = build_report(triaged, sol_path, args.model)

    if args.json:
        print(build_json([] if not findings else triaged))
        return

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"✅ report written to {args.out}")
    else:
        print("\n" + report)


if __name__ == "__main__":
    main()
