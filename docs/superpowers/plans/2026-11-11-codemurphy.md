# CodeMurphy Implementation Plan

> For agentic workers: execute task by task and verify the acceptance tests before publishing.

**Goal:** Ship an independent, reusable PR reviewer with a model comparison harness.
**Architecture:** Separate review inputs, provider calls, evidence validation, and scoring from GitHub delivery.
**Tech stack:** Python 3.11+, standard library at runtime, Git, GitHub Actions.
**Spec:** docs/superpowers/specs/2026-11-11-codemurphy-design.md

## Constraints and review focus

- Quote and anchor both added and deleted lines. Test quoted paths and truncated hunks.
- Report every budget omission. Test an oversized hunk followed by a small file.
- Keep secrets out of prompts and provider errors out of reports.
- Keep PR head changes, spoofed bot markers, and private linked files from publishing.
- Report unknown cost as unknown, incomplete cases separately, and duplicates as false positives.

## Tasks

- [x] **Review inputs and configuration:** add tests for Git diff parsing, bounded batching, exact context refs, path rules, and secret redaction. Implement config, diff and context modules.
- [x] **Review and providers:** test request isolation, evidence validation, disagreement and request failure. Implement deterministic checks, provider adapters and the review engine.
- [x] **GitHub delivery:** test GitHub Files pagination, fork skipping, stale heads, duplicate runs, safe comments and config loading from the base. Implement the API client and composite action.
- [x] **Evaluation:** test one-to-one matching, clean cases, common completed cases, unknown pricing and feedback. Add benchmark fixtures, SQLite history, CLI commands and docs.
- [ ] **Publish:** run the full test suite and offline end-to-end review and benchmark. Validate the action in GitHub, publish an initial version and verify the remote.
