"""Render reports without letting model text become active markup."""
from html import escape
import re
import unicodedata

from .redact import redact


def plain(value):
    text = "".join(c for c in redact(str(value)) if unicodedata.category(c) not in ("Cc", "Cf", "Cs")
                   or c in ("\n", "\t"))
    text = " ".join(text.split()).replace("@", "＠").replace("#", "＃")
    text = re.sub(r"(?i)\b(https?|ftp|mailto):", r"\1：", text)
    text = re.sub(r"(?i)\bwww\.", "www．", text)
    return re.sub(r"([\\`*_\[\]{}()!|~+.-])", r"\\\1", escape(text, quote=False))


def comment(issue, *, language="English"):
    pt = language.casefold().startswith(("pt", "portugu"))
    trigger, impact, fix, check, refs = (
        ("Gatilho", "Impacto", "Correção sugerida", "Como verificar", "Referências") if pt else
        ("Trigger", "Impact", "Suggested change", "How to verify", "References"))
    categories = f"{plain(issue['severity'])} · {plain(issue['category'])}"
    body = f"**{plain(issue['title'])}** ({categories})"
    if issue.get("trigger"):
        fields = ((trigger, "trigger"), (impact, "impact"), (fix, "suggestion"), (check, "verification"))
        body += "".join(f"\n\n**{label}:** {plain(issue[key])}" for label, key in fields)
    else:
        body += f"\n\n{plain(issue['detail'])}\n\n**{fix}:** {plain(issue['suggestion'])}"
    if issue["citations"]:
        entries = [f"{plain(c['repo'])}/{plain(c['path'])}:{c['line']} ({c['commit'][:12]})"
                   for c in issue["citations"]]
        body += f"\n\n**{refs}:** " + ", ".join(entries)
    return body


def markdown(report, *, summary=False, issues=None):
    lines = ["## CodeMurphy"]
    if report.get("skipped"):
        return "\n".join([*lines, "", f"Skipped: {plain(report['skipped'])}.", ""])
    cov = report["coverage"]
    lines += ["", f"Reviewed {cov['reviewed_lines']}/{cov['eligible_lines']} eligible changed lines "
              f"across {cov['files']} changed files; {cov['excluded_files']} excluded files, "
              f"{cov['unreviewable_files']} files without text hunks.",
              f"Context: {report['context_used']}/{report['context_available']} files used.",
              f"Run: `{report['run_id']}`"]
    if cov["partial"]:
        lines.append("**Partial diff:** Some changes could not be reviewed.")
    if report["mode"] == "static":
        lines.append("Deterministic checks only.")
    if report.get("publication"):
        lines.append(f"GitHub review: {plain(report['publication'])}.")
    if report["models"]:
        lines += ["", "| Reviewer | Findings | Failed batches | Tokens in / out | Billed USD | Est. USD | p95 request |",
                  "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for model, stats in report["models"].items():
            def show(val):
                return "—" if val is None else str(val)
            cost = stats["estimated_usd"]
            billed = stats.get("billed_usd")
            ms = stats["p95_latency_ms"]
            lines.append(f"| {plain(model)} | {stats['findings']} | {stats['failed_requests']}/{stats['requests']} | "
                         f"{show(stats['input_tokens'])} / {show(stats['output_tokens'])} | "
                         f"{'—' if billed is None else f'{billed:.6f}'} | "
                         f"{'—' if cost is None else f'{cost:.6f}'} | {'—' if ms is None else f'{ms:.0f} ms'} |")
        for model, stats in report["models"].items():
            if stats["errors"]:
                lines.append(f"\n{plain(model)}: {', '.join(plain(x) for x in stats['errors'])}.")
    if verification := report.get("verification"):
        lines.append(f"\nSecond review ({plain(verification['reviewer'])}): "
                     f"{verification['confirmed']}/{verification['checked']} confirmed, "
                     f"{verification['failed_requests']} failed batches, {verification['withheld']} beyond the cap.")
        if (billed := verification.get("billed_usd")) is not None:
            lines.append(f"Second review billed: USD {billed:.6f}.")
    if summary and report["private_context"]:
        lines.append("\nFindings and paths are omitted because private linked context was loaded.")
        return "\n".join(lines) + "\n"
    for warning in report["warnings"]:
        lines.append(f"\nContext: {plain(warning)}.")
    if issues is None:
        issues = report["findings"]
    if summary:
        if issues:
            lines.append(f"\n{len(issues)} validated finding(s).")
        return "\n".join(lines) + "\n"
    for item in issues:
        lines += ["", f"### {plain(item['path'])}:{item['line']} ({item['side']})", "",
                  comment(item, language=report.get("language", "English")), "", "Reviewers: " + ", ".join(plain(x) for x in item["sources"]),
                  f"Finding ID: `{item['id']}`"]
    if not issues:
        lines.append("\nNo findings met the review policy.")
    return "\n".join(lines) + "\n"
