"""Command-line entry point for local review, GitHub delivery, and evaluation."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

from . import __version__
from .benchmark import BenchmarkError, evaluate, load_suite, read_json
from .config import ConfigError, SEVERITIES, SHA, load_config
from .context import local_refs
from .diff import from_unified
from .github import (GitHub, GitHubError, Skipped, already_reviewed, github_refs,
                     publish, review_publisher, snapshot)
from .gitlocal import GitError, blob_at, root_of, snapshot as git_snapshot
from .history import VERDICTS, feedback, metrics, record
from .redact import redact
from .render import markdown, plain
from .review import publication_findings, run_review

_CONFIG_LIMIT = 128_000


def _write(value, output=None):
    if output:
        Path(output).write_text(value, encoding="utf-8")
    else:
        sys.stdout.write(value)


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _emit(report, args):
    if args.db and not report.get("skipped"):
        record(args.db, report)
    _write(_json(report) if args.format == "json" else markdown(report), args.output)
    if getattr(args, "summary", None):
        with Path(args.summary).open("a", encoding="utf-8") as file:
            file.write(markdown(report, summary=True))


def _requires_models(config, args):
    if not config.models and not args.static_only:
        raise ConfigError("No models configured; set up a trusted config or use --static-only")


def _review_token():
    return (os.getenv("CODEMURPHY_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN") or
            os.getenv("GH_TOKEN"))


def _status(report, threshold, model_ids, findings):
    if (report["coverage"]["partial"] or any(report["models"][m]["failed_requests"] for m in model_ids) or
            (report.get("verification") or {}).get("failed_requests", 0)):
        return 2
    if threshold and any(SEVERITIES.index(f["severity"]) >= SEVERITIES.index(threshold) for f in findings):
        return 1
    return 0


def _local(args):
    root = root_of(args.repo)
    if args.staged and args.head != "HEAD":
        raise ConfigError("--head cannot be used with --staged")
    base, head, raw = git_snapshot(root, args.base, args.head, args.staged)
    if args.config:
        config = load_config(read_json(args.config, _CONFIG_LIMIT))
    elif args.use_base_config:
        config = load_config(blob_at(root, base, ".codemurphy.json", limit=_CONFIG_LIMIT).decode("utf-8"))
    else:
        config = load_config()
    _requires_models(config, args)
    refs, warnings = ((), ()) if args.static_only else local_refs(
        config, root, base, remote=GitHub(os.getenv("CODEMURPHY_CONTEXT_TOKEN") or _review_token()))
    report = run_review(config, from_unified(raw), refs, mode=args.mode, static_only=args.static_only,
                        source={"kind": "git", "repo": redact(root.name), "base": base, "head": head,
                                "staged": args.staged}, warnings=warnings)
    _emit(report, args)
    return _status(report, args.fail_on, report["models"], report["findings"])


def _github(args):
    if args.only_findings and not args.publish:
        raise ConfigError("--only-findings requires --publish")
    if args.use_base_config and not args.trusted_base:
        raise ConfigError("--use-base-config on GitHub requires --trusted-base BRANCH")
    if not (args.static_only or args.config or args.use_base_config):
        raise ConfigError("Select a trusted local --config or explicitly opt in to --use-base-config")
    token = _review_token()
    if args.publish and not token:
        raise ConfigError("Publishing requires CODEMURPHY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN")
    for field, value in (("--expected-head", args.expected_head), ("--expected-base", args.expected_base)):
        if value is not None and not SHA.fullmatch(value):
            raise ConfigError(f"{field} must be a commit SHA")
    api = GitHub(token)
    try:
        pr = snapshot(api, args.repo, args.pr, expected_head=args.expected_head,
                      expected_base=args.expected_base, trusted_base=args.trusted_base, allow_forks=args.allow_forks)
    except Skipped as exc:
        _emit({"schema": 1, "skipped": str(exc)}, args)
        return 0
    publisher = None
    if args.publish:
        publisher = review_publisher(api, args.publisher_login)
        if not args.fail_on and already_reviewed(api, pr, publisher):
            _emit({"schema": 1, "skipped": "This publisher already reviewed the exact base and head"}, args)
            return 0
    if args.config:
        config = load_config(read_json(args.config, _CONFIG_LIMIT))
    elif args.use_base_config:
        try:
            raw = api.blob(pr.repo, pr.base, args.config_path, limit=_CONFIG_LIMIT)
        except GitHubError as exc:
            if exc.status != 404 or not args.static_only:
                raise
            raw = b"{}"
        config = load_config(raw.decode("utf-8"))
        allowed_keys = {None, "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "CODEMURPHY_MODEL_API_KEY"}
        if not args.static_only and any(model.api_key_env not in allowed_keys for model in config.models):
            raise ConfigError("Base-branch config must use a supported model credential environment variable")
    else:
        config = load_config()
    _requires_models(config, args)
    if args.publish and not args.static_only and config.verify_with and args.publish_scope != "primary":
        raise ConfigError("Verified publication requires --publish-scope primary; compare mode still reports shadow models")
    refs, warnings = ((), ()) if args.static_only else github_refs(
        api, GitHub(os.getenv("CODEMURPHY_CONTEXT_TOKEN") or token), pr, config)
    if args.publish and any(r.private for r in refs):
        raise GitHubError("Private linked context requires report-only mode")
    report = run_review(config, pr.files, refs, mode=args.mode, static_only=args.static_only, pr_text=pr.text,
                        source={"kind": "github", "repo": pr.repo, "pr": pr.number,
                                "base": pr.base, "head": pr.head}, warnings=warnings)
    primary = args.publish_scope == "primary" and args.publish
    ids = [config.primary] if primary and not args.static_only else list(report["models"])
    findings = publication_findings(report, args.publish_scope) if args.publish else report["findings"]
    code = _status(report, args.fail_on, ids, findings)
    if args.publish:
        if code == 2:
            report["publication"] = "withheld because review coverage was incomplete"
        elif args.only_findings and (not findings or not config.max_comments):
            report["publication"] = "skipped because there are no publishable findings"
        else:
            try:
                report["publication"] = publish(api, pr, report, config, publisher=publisher,
                                                scope=args.publish_scope)
            except GitHubError as exc:
                code = 2
                report["publication"] = "failed"
                report["warnings"].append(str(exc))
    _emit(report, args)
    return code


def _bench_markdown(result):
    def pct(number):
        return "—" if number is None else f"{number:.1%}"
    lines = [f"## Benchmark: {plain(result['suite'])}", "",
             f"Common completed cases: {len(result['common_cases'])}/{result['case_count']}.",
             f"Suite SHA-256: `{result['suite_sha256']}`", "",
             "| Reviewer | Completed | Precision | Recall | Weighted recall | Est. USD | p95 review |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for label, candidate in result["candidates"].items():
        common = candidate["common"] or {}
        cost, latency = common.get("cost_usd"), common.get("p95_latency_ms")
        lines.append(f"| {plain(label)} | {candidate['completed_cases']} | {pct(common.get('precision'))} | "
                     f"{pct(common.get('recall'))} | {pct(common.get('weighted_recall'))} | "
                     f"{'—' if cost is None else f'{cost:.6f}'} | "
                     f"{'—' if latency is None else f'{latency:.0f} ms'} |")
    return "\n".join(lines) + "\n"


def _bench(args):
    suite = load_suite(args.suite)
    if args.describe:
        _write(_json({"suite": suite.id, "suite_sha256": suite.sha256, "cases": [x.id for x in suite.cases]}),
               args.output)
        return 0
    config = load_config(read_json(args.config, _CONFIG_LIMIT)) if args.config else load_config()
    _requires_models(config, args)
    baselines = {}
    for entry in args.baseline:
        label, sep, file = entry.partition("=")
        if not sep or not file or label in baselines:
            raise BenchmarkError("Use --baseline LABEL=FILE with a unique label")
        baselines[label] = read_json(file)
    result = evaluate(suite, config, static_only=args.static_only, baselines=baselines)
    _write(_json(result) if args.format == "json" else _bench_markdown(result), args.output)
    return 0 if len(result["common_cases"]) == result["case_count"] else 2


def _review_args(parser):
    parser.add_argument("--mode", choices=("primary", "compare"), default="primary",
                        help="Use the primary reviewer or run all models on the same inputs")
    parser.add_argument("--static-only", action="store_true", help="Skip model calls and linked context")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="Exit 1 for findings at this severity or higher")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Write the report to this file")
    parser.add_argument("--db", help="Record telemetry and finding IDs in this SQLite database")


def build_parser():
    parser = argparse.ArgumentParser(prog="codemurphy", description="Evidence-based review and model benchmarking")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    local = sub.add_parser("review", help="Review a Git commit range or the index")
    local.add_argument("--repo", default=".")
    range_args = local.add_mutually_exclusive_group(required=True)
    range_args.add_argument("--base", help="Base ref; compare from the merge base to --head")
    range_args.add_argument("--staged", action="store_true", help="Review the index against HEAD")
    local.add_argument("--head", default="HEAD")
    local_cfg = local.add_mutually_exclusive_group()
    local_cfg.add_argument("--config", help="Explicit trusted config")
    local_cfg.add_argument("--use-base-config", action="store_true",
                           help="Trust .codemurphy.json at the Git base commit")
    _review_args(local)
    local.set_defaults(handler=_local)

    remote = sub.add_parser("github", help="Read a GitHub PR; optionally publish an inline review")
    remote.add_argument("--repo", required=True)
    remote.add_argument("--pr", required=True, type=int)
    remote.add_argument("--expected-head")
    remote.add_argument("--expected-base")
    remote.add_argument("--trusted-base")
    remote.add_argument("--allow-forks", action="store_true")
    remote_cfg = remote.add_mutually_exclusive_group()
    remote_cfg.add_argument("--config", help="Explicit trusted local config")
    remote_cfg.add_argument("--use-base-config", action="store_true",
                            help="Trust remote configuration at --trusted-base")
    remote.add_argument("--config-path", default=".codemurphy.json", help="Path at the PR base commit")
    remote.add_argument("--publish", action="store_true")
    remote.add_argument("--only-findings", action="store_true",
                        help="Skip the GitHub review when there are no publishable findings")
    remote.add_argument("--publish-scope", choices=("primary", "combined"), default="primary")
    remote.add_argument("--publisher-login", help="Bot identity for review deduplication; defaults to GET /user")
    remote.add_argument("--summary", help="Append a redacted summary to this file")
    _review_args(remote)
    remote.set_defaults(handler=_github)

    bench = sub.add_parser("benchmark", help="Score model and imported findings on a labeled suite")
    bench.add_argument("suite")
    bench.add_argument("--config", help="Trusted review/model config; context comes from suite snapshots")
    bench.add_argument("--static-only", action="store_true")
    bench.add_argument("--baseline", action="append", default=[], metavar="LABEL=FILE")
    bench.add_argument("--describe", action="store_true", help="Print the case IDs and suite hash without reviewing")
    bench.add_argument("--format", choices=("markdown", "json"), default="markdown")
    bench.add_argument("--output")
    bench.set_defaults(handler=_bench)

    add = sub.add_parser("record", help="Import a saved JSON review into history")
    add.add_argument("report")
    add.add_argument("--db", required=True)
    add.set_defaults(handler=lambda a: record(a.db, read_json(a.report, 32_000_000)) or 0)
    vote = sub.add_parser("feedback", help="Rate a previously recorded finding")
    vote.add_argument("--db", required=True)
    vote.add_argument("--run", required=True)
    vote.add_argument("--finding", required=True)
    vote.add_argument("--verdict", choices=VERDICTS, required=True)
    vote.set_defaults(handler=lambda a: feedback(a.db, a.run, a.finding, a.verdict) or 0)
    history = sub.add_parser("metrics", help="Aggregate model usage and rated findings")
    history.add_argument("--db", required=True)
    history.add_argument("--repo", help="Filter by the repository shown in the review report")
    history.set_defaults(handler=lambda a: _write(_json(metrics(a.db, a.repo))) or 0)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (BenchmarkError, ConfigError, GitError, GitHubError, OSError, ValueError, KeyError,
            TypeError, AttributeError, sqlite3.Error) as exc:
        message = " ".join(redact(str(exc)).split())
        print(f"codemurphy: {message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
